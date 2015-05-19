/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gummemory.h"
#include "gumprocess.h"

#include <bfd.h>
#include <dlfcn.h>
#include <string.h>
#include <strings.h>
#if defined (HAVE_ELF_H)
# include <elf.h>
#elif defined (HAVE_SYS_ELF_H)
# include <sys/elf.h>
#endif

typedef struct _GumSymbolCollection GumSymbolCollection;

struct _GumSymbolCollection
{
  asymbol ** static_symbols;
  guint num_static_symbols;
  asymbol ** dynamic_symbols;
  guint num_dynamic_symbols;
};

static gpointer do_init (gpointer data);
static void do_deinit (void);

static void gum_build_symbols_database (void);
static gboolean gum_consume_symbols_from_range (const GumRangeDetails * details,
    gpointer user_data);
static void gum_consume_symbols_from_file (const gchar * path,
    gpointer base_address);
static void gum_consume_symbols (bfd * abfd, asymbol ** symbols,
    long num_symbols, gpointer base_address);

static bfd * gum_open_bfd_and_load_symbols (const gchar * path,
    GumSymbolCollection * sc);
static void gum_close_bfd_and_release_symbols (bfd * abfd,
    GumSymbolCollection * sc);

static GHashTable * gum_function_address_by_name = NULL;

static void
gum_symbol_util_init (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, do_init, NULL);
}

static gpointer
do_init (gpointer data)
{
  gum_function_address_by_name = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);

  gum_build_symbols_database ();

  _gum_register_destructor (do_deinit);

  return NULL;
}

static void
do_deinit (void)
{
  g_hash_table_unref (gum_function_address_by_name);
  gum_function_address_by_name = NULL;
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  gboolean result = FALSE;
  Dl_info dl_info;
  const gchar * module_name;
  bfd * abfd = NULL;
  GumSymbolCollection sc = { 0, };
  bfd_vma offset;
  asection * section;

  gum_symbol_util_init ();

  if (!dladdr (address, &dl_info))
    goto beach;

  memset (details, 0, sizeof (GumSymbolDetails));

  details->address = GUM_ADDRESS (address);

  module_name = rindex (dl_info.dli_fname, '/');
  if (module_name != NULL)
    module_name++;
  else
    module_name = dl_info.dli_fname;
  g_strlcpy (details->module_name, module_name, sizeof (details->module_name));

  result = TRUE;

  abfd = gum_open_bfd_and_load_symbols (dl_info.dli_fname, &sc);
  if (abfd == NULL)
    goto beach;

  offset = GPOINTER_TO_SIZE (address);
  if (abfd->flags & BSF_KEEP_G)
    offset -= GPOINTER_TO_SIZE (dl_info.dli_fbase);

  for (section = abfd->sections; section != NULL; section = section->next)
  {
    bfd_vma section_start;
    bfd_size_type section_size;
    const gchar * file_name;
    const gchar * symbol_name;
    guint line_number;

    section_start = bfd_get_section_vma (abfd, section);
    if (offset < section_start)
      continue;

    section_size = bfd_get_section_size (section);
    if (offset >= section_start + section_size)
      continue;

    if (bfd_find_nearest_line (abfd, section, sc.static_symbols,
        offset - section_start, &file_name, &symbol_name, &line_number) ||
        bfd_find_nearest_line (abfd, section, sc.dynamic_symbols,
        offset - section_start, &file_name, &symbol_name, &line_number))
    {
      if (symbol_name != NULL)
      {
        g_strlcpy (details->symbol_name, symbol_name,
            sizeof (details->symbol_name));
      }

      if (file_name != NULL)
        g_strlcpy (details->file_name, file_name, sizeof (details->file_name));

      details->line_number = line_number;

      break;
    }
  }

beach:
  gum_close_bfd_and_release_symbols (abfd, &sc);
  return result;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  GumSymbolDetails details;

  if (gum_symbol_details_from_address (address, &details))
    return g_strdup (details.symbol_name);
  else
    return NULL;
}

gpointer
gum_find_function (const gchar * name)
{
  gum_symbol_util_init ();

  return g_hash_table_lookup (gum_function_address_by_name, name);
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * matches;
  gpointer address;

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  address = gum_find_function (name);
  if (address != NULL)
    g_array_append_val (matches, address);

  return matches;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * matches;
  GPatternSpec * pspec;
  GHashTableIter iter;
  const gchar * function_name;
  gpointer function_address;

  gum_symbol_util_init ();

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));

  pspec = g_pattern_spec_new (str);

  g_hash_table_iter_init (&iter, gum_function_address_by_name);
  while (g_hash_table_iter_next (&iter, (gpointer *) &function_name,
      &function_address))
  {
    if (g_pattern_match_string (pspec, function_name))
      g_array_append_val (matches, function_address);
  }

  g_pattern_spec_free (pspec);

  return matches;
}

static void
gum_build_symbols_database (void)
{
  g_hash_table_remove_all (gum_function_address_by_name);

  gum_process_enumerate_ranges (GUM_PAGE_RX, gum_consume_symbols_from_range,
      NULL);
}

static gboolean
gum_consume_symbols_from_range (const GumRangeDetails * details,
                                gpointer user_data)
{
  gpointer header;
  guint16 type;
  gpointer base_address;

  if (details->file == NULL || details->file->offset != 0)
    return TRUE;

  header = GSIZE_TO_POINTER (details->range->base_address);
  if (memcmp (header, ELFMAG, SELFMAG) != 0)
    return TRUE;

  type = *((guint16 *) (header + EI_NIDENT));
  if (type != ET_EXEC && type != ET_DYN)
    return TRUE;

  if (type == ET_DYN)
    base_address = GSIZE_TO_POINTER (details->range->base_address);
  else
    base_address = NULL;
  gum_consume_symbols_from_file (details->file->path, base_address);

  return TRUE;
}

static void
gum_consume_symbols_from_file (const gchar * path,
                               gpointer base_address)
{
  bfd * abfd = NULL;
  GumSymbolCollection sc = { 0, };

  abfd = gum_open_bfd_and_load_symbols (path, &sc);
  if (abfd != NULL)
  {
    gum_consume_symbols (abfd, sc.static_symbols, sc.num_static_symbols,
        base_address);
    gum_consume_symbols (abfd, sc.dynamic_symbols, sc.num_dynamic_symbols,
        base_address);
  }

  gum_close_bfd_and_release_symbols (abfd, &sc);
}

static void
gum_consume_symbols (bfd * abfd,
                     asymbol ** symbols,
                     long num_symbols,
                     gpointer base_address)
{
  long i;
  gpointer address;
#ifdef HAVE_ARM
  GHashTable * thumb_symbols;

  thumb_symbols = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  for (i = 0; i != num_symbols; i++)
  {
    asymbol * sym = symbols[i];

    if (bfd_is_target_special_symbol (abfd, sym) &&
        sym->name[0] == '$' && sym->name[1] == 't')
    {
      address = base_address + bfd_asymbol_value (sym);
      g_hash_table_insert (thumb_symbols, address, address);
    }
  }
#endif

  for (i = 0; i != num_symbols; i++)
  {
    asymbol * sym = symbols[i];

    if (sym->name == NULL || sym->name[0] == '\0')
      continue;
    else if ((sym->flags & BSF_FUNCTION) == 0)
      continue;
    else if ((sym->flags & (BSF_LOCAL | BSF_GLOBAL)) == 0)
      continue;

    address = (guint8 *) base_address + bfd_asymbol_value (sym);
    if (address == NULL)
      continue;
#ifdef HAVE_ARM
    if (g_hash_table_contains (thumb_symbols, address))
      address++;
#endif

    g_hash_table_insert (gum_function_address_by_name, g_strdup (sym->name),
        address);
  }

#ifdef HAVE_ARM
  g_hash_table_unref (thumb_symbols);
#endif
}

static bfd *
gum_open_bfd_and_load_symbols (const gchar * path,
                               GumSymbolCollection * sc)
{
  bfd * abfd;
  long static_size, dynamic_size;

  memset (sc, 0, sizeof (GumSymbolCollection));

  abfd = bfd_openr (path, NULL);
  if (abfd == NULL || !bfd_check_format (abfd, bfd_object))
    goto open_failed;

  static_size = bfd_get_symtab_upper_bound (abfd);
  if (static_size > 0)
  {
    sc->static_symbols = g_malloc (static_size);
    sc->num_static_symbols = bfd_canonicalize_symtab (abfd,
        sc->static_symbols);
  }

  dynamic_size = bfd_get_dynamic_symtab_upper_bound (abfd);
  if (dynamic_size > 0)
  {
    sc->dynamic_symbols = g_malloc (dynamic_size);
    sc->num_dynamic_symbols = bfd_canonicalize_dynamic_symtab (abfd,
        sc->dynamic_symbols);
  }

  if (sc->num_static_symbols + sc->num_dynamic_symbols == 0)
    goto open_failed;

  return abfd;

open_failed:
  gum_close_bfd_and_release_symbols (abfd, sc);
  return NULL;
}

static void
gum_close_bfd_and_release_symbols (bfd * abfd,
                                   GumSymbolCollection * sc)
{
  if (abfd != NULL)
    bfd_close (abfd);

  g_free (sc->static_symbols);
  g_free (sc->dynamic_symbols);
}
