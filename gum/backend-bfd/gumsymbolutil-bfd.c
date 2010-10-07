/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#define _GNU_SOURCE

#include "gumsymbolutil.h"

#include "gummemory.h"
#include "gumsymbolutil-priv.h"

#include <bfd.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <strings.h>

typedef struct _SymbolCollection SymbolCollection;

struct _SymbolCollection
{
  asymbol ** static_symbols;
  guint num_static_symbols;
  asymbol ** dynamic_symbols;
  guint num_dynamic_symbols;
};

static void build_symbols_database (void);
static int add_symbols_for_shared_object (struct dl_phdr_info * info,
    size_t size, void * data);
static void add_symbols_for_file (const gchar * filename,
    gpointer base_address);
static void add_interesting_symbols (bfd * abfd, asymbol ** symbols,
    long num_symbols, gpointer base_address);
static void maybe_add_function_symbol (bfd * abfd, asymbol * sym,
    gpointer base_address);

static bfd * open_bfd_and_load_symbols (const gchar * filename,
    SymbolCollection * sc);
static void close_bfd_and_release_symbols (bfd * abfd, SymbolCollection * sc);

static GHashTable * function_address_by_name_ht = NULL;

void
_gum_symbol_util_init (void)
{
  function_address_by_name_ht = g_hash_table_new_full (g_str_hash,
      g_str_equal, g_free, NULL);

  build_symbols_database ();
}

void
_gum_symbol_util_deinit (void)
{
  g_hash_table_unref (function_address_by_name_ht);
  function_address_by_name_ht = NULL;
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  gboolean result = FALSE;
  Dl_info dl_info;
  const gchar * module_name;
  bfd * abfd = NULL;
  SymbolCollection sc = { 0, };
  bfd_vma offset;
  asection * section;

  if (!dladdr (address, &dl_info))
    goto beach;

  memset (details, 0, sizeof (GumSymbolDetails));

  details->address = address;

  module_name = rindex (dl_info.dli_fname, '/');
  if (module_name != NULL)
    module_name++;
  else
    module_name = dl_info.dli_fname;
  g_strlcpy (details->module_name, module_name, sizeof (details->module_name));

  result = TRUE;

  abfd = open_bfd_and_load_symbols (dl_info.dli_fname, &sc);
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
  close_bfd_and_release_symbols (abfd, &sc);
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
  return g_hash_table_lookup (function_address_by_name_ht, name);
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * matches;
  GRegex * regex;

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));

  regex = g_regex_new (str, 0, G_REGEX_MATCH_ANCHORED, NULL);
  if (regex != NULL)
  {
    GHashTableIter iter;
    const gchar * function_name;
    gpointer function_address;

    g_hash_table_iter_init (&iter, function_address_by_name_ht);
    while (g_hash_table_iter_next (&iter, (gpointer *) &function_name,
        &function_address))
    {
      if (g_regex_match (regex, function_name, 0, NULL))
        g_array_append_val (matches, function_address);
    }

    g_regex_unref (regex);
  }

  return matches;
}

static void
build_symbols_database (void)
{
  g_hash_table_remove_all (function_address_by_name_ht);

  add_symbols_for_file ("/proc/self/exe", NULL);

  dl_iterate_phdr (add_symbols_for_shared_object, NULL);
}

static int
add_symbols_for_shared_object (struct dl_phdr_info * info,
                               size_t size,
                               void * data)
{
  if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
  {
    gpointer base_address = GSIZE_TO_POINTER (info->dlpi_addr);
    add_symbols_for_file (info->dlpi_name, base_address);
  }

  return 0;
}

static void
add_symbols_for_file (const gchar * filename,
                      gpointer base_address)
{
  bfd * abfd = NULL;
  SymbolCollection sc = { 0, };

  abfd = open_bfd_and_load_symbols (filename, &sc);
  if (abfd != NULL)
  {
    add_interesting_symbols (abfd, sc.static_symbols, sc.num_static_symbols,
        base_address);
    add_interesting_symbols (abfd, sc.dynamic_symbols, sc.num_dynamic_symbols,
        base_address);
  }

  close_bfd_and_release_symbols (abfd, &sc);
}

static void
add_interesting_symbols (bfd * abfd,
                         asymbol ** symbols,
                         long num_symbols,
                         gpointer base_address)
{
  long i;

  for (i = 0; i < num_symbols; i++)
  {
    asymbol * sym = symbols[i];

    if (sym->name == NULL || sym->name[0] == '\0')
      continue;

    maybe_add_function_symbol (abfd, sym, base_address);
  }
}

static void
maybe_add_function_symbol (bfd * abfd,
                           asymbol * sym,
                           gpointer base_address)
{
  if ((sym->flags & BSF_FUNCTION) == 0)
    return;
  if ((sym->flags & (BSF_LOCAL | BSF_GLOBAL)) == 0)
    return;

  g_hash_table_insert (function_address_by_name_ht, g_strdup (sym->name),
      (guint8 *) base_address + bfd_asymbol_value (sym));
}

static bfd *
open_bfd_and_load_symbols (const gchar * filename,
                           SymbolCollection * sc)
{
  bfd * abfd;
  long static_size, dynamic_size;

  memset (sc, 0, sizeof (SymbolCollection));

  abfd = bfd_openr (filename, NULL);
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
  close_bfd_and_release_symbols (abfd, sc);
  return NULL;
}

static void
close_bfd_and_release_symbols (bfd * abfd,
                               SymbolCollection * sc)
{
  if (abfd != NULL)
    bfd_close (abfd);

  g_free (sc->static_symbols);
  g_free (sc->dynamic_symbols);
}
