/*
 * Copyright (C) 2017-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "backend-elf/gumelfmodule.h"
#include "gum-init.h"

#include <dlfcn.h>
#include <dwarf.h>
#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include <libdwarf.h>
#ifdef __clang__
# pragma clang diagnostic pop
#endif
#include <strings.h>

#define GUM_MAX_CACHE_AGE (0.5)

typedef struct _GumModuleEntry GumModuleEntry;

typedef struct _GumNearestSymbolDetails GumNearestSymbolDetails;
typedef struct _GumDwarfSymbolDetails GumDwarfSymbolDetails;
typedef struct _GumDwarfSourceDetails GumDwarfSourceDetails;
typedef struct _GumFindCuDieOperation GumFindCuDieOperation;
typedef struct _GumFindSymbolOperation GumFindSymbolOperation;

typedef struct _GumCuDieDetails GumCuDieDetails;
typedef struct _GumDieDetails GumDieDetails;

typedef gboolean (* GumFoundCuDieFunc) (const GumCuDieDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundDieFunc) (const GumDieDetails * details,
    gpointer user_data);

struct _GumModuleEntry
{
  GumElfModule * module;
  Dwarf_Debug dbg;
  gboolean collected;
};

struct _GumNearestSymbolDetails
{
  const gchar * name;
  gpointer address;
};

struct _GumDwarfSymbolDetails
{
  gchar * name;
  guint line_number;
};

struct _GumDwarfSourceDetails
{
  gchar * path;
  guint line_number;
};

struct _GumFindCuDieOperation
{
  Dwarf_Addr needle;
  gboolean found;
  Dwarf_Off cu_die_offset;
};

struct _GumFindSymbolOperation
{
  GumAddress needle;
  GumDwarfSymbolDetails * symbol;
  GumAddress closest_address;
};

struct _GumCuDieDetails
{
  Dwarf_Die cu_die;

  Dwarf_Debug dbg;
};

struct _GumDieDetails
{
  Dwarf_Die die;
  Dwarf_Half tag;

  Dwarf_Debug dbg;
};

static gboolean gum_find_nearest_symbol_by_address (gpointer address,
    GumNearestSymbolDetails * nearest);
static GumModuleEntry * gum_module_entry_from_address (gpointer address,
    GumNearestSymbolDetails * nearest);
static GumModuleEntry * gum_module_entry_from_path_and_base (const gchar * path,
    GumAddress base_address);

static GHashTable * gum_get_function_addresses (void);
static GHashTable * gum_get_address_symbols (void);
static void gum_maybe_refresh_symbol_caches (void);
static gboolean gum_collect_module_functions (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_collect_symbol_if_function (
    const GumElfSymbolDetails * details, gpointer user_data);

static void gum_symbol_util_ensure_initialized (void);
static void gum_symbol_util_deinitialize (void);

static void gum_on_dwarf_error (Dwarf_Error error, Dwarf_Ptr errarg);

static Dwarf_Die gum_find_cu_die_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Addr address);
static gboolean gum_store_cu_die_offset_if_containing_address (
    const GumCuDieDetails * details, GumFindCuDieOperation * op);
static gboolean gum_find_symbol_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Die cu_die, Dwarf_Addr address, GumDwarfSymbolDetails * details);
static gboolean gum_collect_die_if_closest_so_far (
    const GumDieDetails * details, GumFindSymbolOperation * op);
static gboolean gum_find_line_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Die cu_die, Dwarf_Addr address, guint symbol_line_number,
    GumDwarfSourceDetails * details);

static void gum_enumerate_cu_dies (Dwarf_Debug dbg, gboolean is_info,
    GumFoundCuDieFunc func, gpointer user_data);
static void gum_enumerate_dies (Dwarf_Debug dbg, Dwarf_Die die,
    GumFoundDieFunc func, gpointer user_data);
static gboolean gum_enumerate_dies_recurse (Dwarf_Debug dbg, Dwarf_Die die,
    GumFoundDieFunc func, gpointer user_data);

static gboolean gum_read_die_name (Dwarf_Debug dbg, Dwarf_Die die,
    gchar ** name);
static gboolean gum_read_attribute_location (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Addr * address);
static gboolean gum_read_attribute_address (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Addr * address);
static gboolean gum_read_attribute_offset (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Off * offset);
static gboolean gum_read_attribute_uint (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Unsigned * value);

static gint gum_compare_pointers (gconstpointer a, gconstpointer b);

G_LOCK_DEFINE_STATIC (gum_symbol_util);
static GHashTable * gum_module_entries = NULL;
static GHashTable * gum_function_addresses = NULL;
static GHashTable * gum_address_symbols = NULL;
static GTimer * gum_cache_timer = NULL;

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  gboolean success;
  GumModuleEntry * entry;
  GumNearestSymbolDetails nearest;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;
  GumDwarfSymbolDetails symbol;
  GumDwarfSourceDetails source;

  success = FALSE;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address, &nearest);
  if (entry == NULL)
    goto entry_not_found;
  if (entry->dbg == NULL)
    goto no_debug_info;

  file_address = gum_elf_module_translate_to_offline (entry->module,
      GUM_ADDRESS (address));

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  if (!gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol))
    goto symbol_not_found;

  if (!gum_find_line_by_virtual_address (entry->dbg, cu_die, file_address,
      symbol.line_number, &source))
    goto line_not_found;

  details->address = GUM_ADDRESS (address);

  g_strlcpy (details->module_name, gum_elf_module_get_name (entry->module),
      sizeof (details->module_name));
  g_strlcpy (details->symbol_name, symbol.name, sizeof (details->symbol_name));

  g_strlcpy (details->file_name, source.path, sizeof (details->file_name));
  details->line_number = source.line_number;

  success = TRUE;

  g_free (source.path);

line_not_found:
  g_free (symbol.name);

symbol_not_found:
  dwarf_dealloc (entry->dbg, cu_die, DW_DLA_DIE);

cu_die_not_found:
  if (!success)
    goto no_debug_info;

entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return success;

no_debug_info:
  {
    gsize offset;

    details->address = GUM_ADDRESS (address);

    g_strlcpy (details->module_name, gum_elf_module_get_name (entry->module),
        sizeof (details->module_name));

    if (nearest.name == NULL)
      gum_find_nearest_symbol_by_address (address, &nearest);

    if (nearest.name != NULL)
    {
      offset = GPOINTER_TO_SIZE (address) - GPOINTER_TO_SIZE (nearest.address);

      if (offset == 0)
      {
        g_strlcpy (details->symbol_name, nearest.name,
            sizeof (details->symbol_name));
      }
      else
      {
        g_snprintf (details->symbol_name, sizeof (details->symbol_name),
            "%s+0x%" G_GSIZE_MODIFIER "x", nearest.name, offset);
      }
    }
    else
    {
      offset = details->address -
          gum_elf_module_get_base_address (entry->module);

      g_snprintf (details->symbol_name, sizeof (details->symbol_name),
          "0x%" G_GSIZE_MODIFIER "x", offset);
    }

    details->file_name[0] = '\0';
    details->line_number = 0;

    G_UNLOCK (gum_symbol_util);

    return TRUE;
  }
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  GumDwarfSymbolDetails symbol;
  GumModuleEntry * entry;
  GumNearestSymbolDetails nearest;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;

  symbol.name = NULL;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address, &nearest);
  if (entry == NULL)
    goto entry_not_found;
  if (entry->dbg == NULL)
    goto no_debug_info;

  file_address = gum_elf_module_translate_to_offline (entry->module,
      GUM_ADDRESS (address));

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol);

  dwarf_dealloc (entry->dbg, cu_die, DW_DLA_DIE);

cu_die_not_found:
  if (symbol.name == NULL)
    goto no_debug_info;

entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return symbol.name;

no_debug_info:
  {
    gsize offset;

    if (nearest.name == NULL)
      gum_find_nearest_symbol_by_address (address, &nearest);

    if (nearest.name != NULL)
    {
      offset = GPOINTER_TO_SIZE (address) - GPOINTER_TO_SIZE (nearest.address);

      if (offset == 0)
      {
        symbol.name = g_strdup (nearest.name);
      }
      else
      {
        symbol.name = g_strdup_printf ("%s+0x%" G_GSIZE_MODIFIER "x",
            nearest.name, offset);
      }
    }
    else
    {
      offset = GPOINTER_TO_SIZE (address) -
          gum_elf_module_get_base_address (entry->module);

      symbol.name = g_strdup_printf ("0x%" G_GSIZE_MODIFIER "x", offset);
    }

    G_UNLOCK (gum_symbol_util);

    return symbol.name;
  }
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer address;
  GArray * addresses;

  address = NULL;

  G_LOCK (gum_symbol_util);

  addresses = g_hash_table_lookup (gum_get_function_addresses (), name);

  if (addresses != NULL)
  {
    address = g_array_index (addresses, gpointer, 0);
  }

  G_UNLOCK (gum_symbol_util);

  return address;
}

static gboolean
gum_find_nearest_symbol_by_address (gpointer address,
                                    GumNearestSymbolDetails * nearest)
{
  GHashTable * table;
  GumElfSymbolDetails * details;
  GHashTableIter iter;
  gpointer value;

  table = gum_get_address_symbols ();

  details = g_hash_table_lookup (table, address);
  if (details != NULL)
  {
    nearest->name = details->name;
    nearest->address = address;
    return TRUE;
  }

  g_hash_table_iter_init (&iter, table);
  while (g_hash_table_iter_next (&iter, NULL, &value))
  {
    GumElfSymbolDetails * current_symbol = value;

    if (current_symbol->address > GUM_ADDRESS (address))
      continue;

    if (current_symbol->address + current_symbol->size <= GUM_ADDRESS (address))
    {
      continue;
    }

    nearest->address = GSIZE_TO_POINTER (current_symbol->address);
    nearest->name = current_symbol->name;
    return TRUE;
  }

  return FALSE;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * result, * addresses;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  G_LOCK (gum_symbol_util);

  addresses = g_hash_table_lookup (gum_get_function_addresses (), name);

  if (addresses != NULL)
  {
    g_array_append_vals (result, addresses->data, addresses->len);
  }

  G_UNLOCK (gum_symbol_util);

  return result;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * matches;
  GHashTable * seen;
  GPatternSpec * pspec;
  GHashTableIter iter;
  gpointer key, value;

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  seen = g_hash_table_new (NULL, NULL);
  pspec = g_pattern_spec_new (str);

  G_LOCK (gum_symbol_util);

  g_hash_table_iter_init (&iter, gum_get_function_addresses ());
  while (g_hash_table_iter_next (&iter, &key, &value))
  {
    const gchar * name = key;
    GArray * addresses = value;

    if (g_pattern_match_string (pspec, name))
    {
      guint i;

      for (i = 0; i != addresses->len; i++)
      {
        gpointer address;

        address = g_array_index (addresses, gpointer, i);

        if (!g_hash_table_contains (seen, address))
        {
          g_array_append_val (matches, address);

          g_hash_table_add (seen, address);
        }
      }
    }
  }

  G_UNLOCK (gum_symbol_util);

  g_array_sort (matches, gum_compare_pointers);

  g_pattern_spec_free (pspec);
  g_hash_table_unref (seen);

  return matches;
}

gboolean
gum_load_symbols (const gchar * path)
{
  return FALSE;
}

static GumModuleEntry *
gum_module_entry_from_address (gpointer address,
                               GumNearestSymbolDetails * nearest)
{
  GumModuleEntry * entry;
  Dl_info dl_info;
  const gchar * path;
  gchar * path_malloc_data;

  if (dladdr (address, &dl_info) == 0)
  {
    nearest->name = NULL;
    nearest->address = NULL;
    return NULL;
  }

  nearest->name = dl_info.dli_sname;
  nearest->address = dl_info.dli_saddr;

  path = dl_info.dli_fname;
  if (!g_path_is_absolute (path))
  {
    path_malloc_data = g_canonicalize_filename (path, NULL);
    path = path_malloc_data;
  }
  else
  {
    path_malloc_data = NULL;
  }

  entry = gum_module_entry_from_path_and_base (path,
      GUM_ADDRESS (dl_info.dli_fbase));

  g_free (path_malloc_data);

  return entry;
}

static GumModuleEntry *
gum_module_entry_from_path_and_base (const gchar * path,
                                     GumAddress base_address)
{
  GumModuleEntry * entry;
  GumElfModule * module;
  Dwarf_Debug dbg = NULL;
  Dwarf_Error error = NULL;

  gum_symbol_util_ensure_initialized ();

  entry = g_hash_table_lookup (gum_module_entries, path);
  if (entry != NULL)
    goto have_entry;

  module = gum_elf_module_new_from_memory (path, base_address, NULL);

  if (module == NULL ||
      dwarf_elf_init_b (gum_elf_module_get_elf (module), DW_DLC_READ,
          DW_GROUPNUMBER_ANY, gum_on_dwarf_error, NULL, &dbg, &error)
      != DW_DLV_OK)
  {
    dwarf_dealloc (dbg, error, DW_DLA_ERROR);
    error = NULL;
  }

  entry = g_slice_new (GumModuleEntry);
  entry->module = module;
  entry->dbg = dbg;
  entry->collected = FALSE;

  g_hash_table_insert (gum_module_entries, g_strdup (path), entry);

have_entry:
  return (entry->module != NULL) ? entry : NULL;
}

static void
gum_module_entry_free (GumModuleEntry * entry)
{
  if (entry->dbg != NULL)
    dwarf_finish (entry->dbg, NULL);

  if (entry->module != NULL)
    gum_object_unref (entry->module);

  g_slice_free (GumModuleEntry, entry);
}

static GHashTable *
gum_get_function_addresses (void)
{
  gum_maybe_refresh_symbol_caches ();
  return gum_function_addresses;
}

static GHashTable *
gum_get_address_symbols (void)
{
  gum_maybe_refresh_symbol_caches ();
  return gum_address_symbols;
}

static void
gum_maybe_refresh_symbol_caches (void)
{
  gboolean need_update;

  gum_symbol_util_ensure_initialized ();

  if (gum_cache_timer == NULL)
  {
    gum_cache_timer = g_timer_new ();

    need_update = TRUE;
  }
  else
  {
    need_update = g_timer_elapsed (gum_cache_timer, NULL) >= GUM_MAX_CACHE_AGE;
  }

  if (need_update)
  {
    gum_process_enumerate_modules (gum_collect_module_functions, NULL);
  }
}

static gboolean
gum_collect_module_functions (const GumModuleDetails * details,
                              gpointer user_data)
{
  GumModuleEntry * entry;

  entry = gum_module_entry_from_path_and_base (details->path,
      details->range->base_address);
  if (entry == NULL || entry->collected)
    return TRUE;

  gum_elf_module_enumerate_dynamic_symbols (entry->module,
      gum_collect_symbol_if_function, NULL);

  gum_elf_module_enumerate_symbols (entry->module,
      gum_collect_symbol_if_function, NULL);

  entry->collected = TRUE;

  return TRUE;
}

static gboolean
gum_collect_symbol_if_function (const GumElfSymbolDetails * details,
                                gpointer user_data)
{
  const gchar * name;
  gpointer address;
  GArray * addresses;
  gboolean already_collected;
  GumElfSymbolDetails * address_symbol;

  if (details->section_header_index == GUM_ELF_SECTION_HEADER_INDEX_NONE ||
      details->type != GUM_ELF_SYMBOL_FUNC)
    return TRUE;

  name = details->name;
  address = GSIZE_TO_POINTER (details->address);

  already_collected = FALSE;

  addresses = g_hash_table_lookup (gum_function_addresses, name);
  if (addresses == NULL)
  {
    addresses = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), 1);
    g_hash_table_insert (gum_function_addresses, g_strdup (name), addresses);
  }
  else
  {
    guint i;

    for (i = 0; i != addresses->len; i++)
    {
      if (g_array_index (addresses, gpointer, i) == address)
      {
        already_collected = TRUE;
        break;
      }
    }
  }

  if (!already_collected)
    g_array_append_val (addresses, address);

  address_symbol = g_hash_table_lookup (gum_address_symbols, address);
  if (address_symbol == NULL)
  {
    address_symbol = g_slice_new (GumElfSymbolDetails);
    address_symbol->name = g_strdup (name);
    address_symbol->address = details->address;
    address_symbol->size = details->size;
    address_symbol->type = details->type;
    address_symbol->bind = details->bind;
    address_symbol->section_header_index = details->section_header_index;
    g_hash_table_insert (gum_address_symbols, address, address_symbol);
  }
    
  return TRUE;
}

static void
gum_function_addresses_free (GArray * addresses)
{
  g_array_free (addresses, TRUE);
}

static void
gum_address_symbols_value_free (GumElfSymbolDetails * details)
{
  g_free ((gpointer) details->name);
  g_slice_free (GumElfSymbolDetails, details);
}

static void
gum_symbol_util_ensure_initialized (void)
{
  if (gum_module_entries != NULL)
    return;

  gum_module_entries = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_module_entry_free);
  gum_function_addresses = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_function_addresses_free);
  gum_address_symbols = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, (GDestroyNotify) gum_address_symbols_value_free);

  _gum_register_destructor (gum_symbol_util_deinitialize);
}

static void
gum_symbol_util_deinitialize (void)
{
  g_clear_pointer (&gum_cache_timer, g_timer_destroy);

  g_hash_table_unref (gum_address_symbols);
  gum_address_symbols = NULL;

  g_hash_table_unref (gum_function_addresses);
  gum_function_addresses = NULL;

  g_hash_table_unref (gum_module_entries);
  gum_module_entries = NULL;
}

static void
gum_on_dwarf_error (Dwarf_Error error,
                    Dwarf_Ptr errarg)
{
}

static Dwarf_Die
gum_find_cu_die_by_virtual_address (Dwarf_Debug dbg,
                                    Dwarf_Addr address)
{
  Dwarf_Die result;
  GumFindCuDieOperation op;

  op.needle = address;
  op.found = FALSE;
  op.cu_die_offset = 0;

  gum_enumerate_cu_dies (dbg, TRUE,
      (GumFoundCuDieFunc) gum_store_cu_die_offset_if_containing_address, &op);

  if (!op.found)
    return NULL;

  result = NULL;
  dwarf_offdie (dbg, op.cu_die_offset, &result, NULL);

  return result;
}

static gboolean
gum_store_cu_die_offset_if_containing_address (const GumCuDieDetails * details,
                                               GumFindCuDieOperation * op)
{
  Dwarf_Debug dbg = details->dbg;
  Dwarf_Die die = details->cu_die;
  Dwarf_Addr low_pc, high_pc;
  Dwarf_Attribute high_pc_attr;
  Dwarf_Off ranges_offset;
  Dwarf_Ranges * ranges;
  Dwarf_Signed range_count, range_index;

  if (gum_read_attribute_address (dbg, die, DW_AT_low_pc, &low_pc) &&
      dwarf_attr (die, DW_AT_high_pc, &high_pc_attr, NULL) == DW_DLV_OK)
  {
    Dwarf_Half form;

    dwarf_whatform (high_pc_attr, &form, NULL);
    if (form == DW_FORM_addr)
    {
      dwarf_formaddr (high_pc_attr, &high_pc, NULL);
    }
    else
    {
      Dwarf_Unsigned offset;

      dwarf_formudata (high_pc_attr, &offset, NULL);

      high_pc = low_pc + offset;
    }

    if (op->needle >= low_pc && op->needle < high_pc)
    {
      op->found = TRUE;
      dwarf_dieoffset (die, &op->cu_die_offset, NULL);
    }

    return !op->found;
  }

  if (!gum_read_attribute_offset (dbg, die, DW_AT_ranges, &ranges_offset))
    goto skip;

  if (dwarf_get_ranges_a (dbg, ranges_offset, die, &ranges, &range_count, NULL,
      NULL) != DW_DLV_OK)
    goto skip;

  for (range_index = 0; range_index < range_count; range_index++)
  {
    Dwarf_Ranges * range = &ranges[range_index];

    if (range->dwr_type != DW_RANGES_ENTRY)
      break;

    if (op->needle >= range->dwr_addr1 && op->needle < range->dwr_addr2)
    {
      op->found = TRUE;
      dwarf_dieoffset (die, &op->cu_die_offset, NULL);

      break;
    }
  }

  dwarf_ranges_dealloc (dbg, ranges, range_count);

skip:
  return !op->found;
}

static gboolean
gum_find_symbol_by_virtual_address (Dwarf_Debug dbg,
                                    Dwarf_Die cu_die,
                                    Dwarf_Addr address,
                                    GumDwarfSymbolDetails * details)
{
  GumFindSymbolOperation op;

  details->name = NULL;
  details->line_number = 0;

  op.needle = address;
  op.symbol = details;
  op.closest_address = 0;

  gum_enumerate_dies (dbg, cu_die,
      (GumFoundDieFunc) gum_collect_die_if_closest_so_far, &op);

  return details->name != NULL;
}

static gboolean
gum_collect_die_if_closest_so_far (const GumDieDetails * details,
                                   GumFindSymbolOperation * op)
{
  Dwarf_Debug dbg = details->dbg;
  Dwarf_Die die = details->die;
  GumDwarfSymbolDetails * symbol = op->symbol;
  Dwarf_Half tag;
  Dwarf_Addr address;

  if (dwarf_tag (die, &tag, NULL) != DW_DLV_OK)
    return TRUE;

  if (tag == DW_TAG_subprogram)
  {
    if (!gum_read_attribute_address (dbg, die, DW_AT_low_pc, &address))
      return TRUE;
  }
  else if (tag == DW_TAG_variable)
  {
    if (!gum_read_attribute_location (dbg, die, DW_AT_location, &address))
      return TRUE;
  }
  else
  {
    return TRUE;
  }

  if (op->needle < address)
    return TRUE;

  if (op->closest_address == 0 ||
      (op->needle - address) < (op->needle - op->closest_address))
  {
    Dwarf_Unsigned line_number;

    op->closest_address = address;

    g_clear_pointer (&symbol->name, g_free);
    gum_read_die_name (dbg, die, &symbol->name);

    if (gum_read_attribute_uint (dbg, die, DW_AT_decl_line, &line_number))
    {
      symbol->line_number = line_number;
    }
  }

  return TRUE;
}

static gboolean
gum_find_line_by_virtual_address (Dwarf_Debug dbg,
                                  Dwarf_Die cu_die,
                                  Dwarf_Addr address,
                                  guint symbol_line_number,
                                  GumDwarfSourceDetails * details)
{
  gboolean success;
  Dwarf_Line * lines;
  Dwarf_Signed line_count, line_index;

  if (dwarf_srclines (cu_die, &lines, &line_count, NULL) != DW_DLV_OK)
    return FALSE;

  success = FALSE;

  for (line_index = 0; line_index != line_count; line_index++)
  {
    Dwarf_Line line = lines[line_index];
    Dwarf_Addr line_address;

    if (dwarf_lineaddr (line, &line_address, NULL) != DW_DLV_OK)
      continue;

    if (line_address >= address)
    {
      Dwarf_Unsigned line_number;
      char * path;

      if (dwarf_lineno (line, &line_number, NULL) != DW_DLV_OK)
        continue;

      if (line_number < symbol_line_number)
        continue;

      if (dwarf_linesrc (line, &path, NULL) != DW_DLV_OK)
        continue;

      details->path = g_strdup (path);
      details->line_number = line_number;

      success = TRUE;

      dwarf_dealloc (dbg, path, DW_DLA_STRING);

      break;
    }
  }

  dwarf_srclines_dealloc (dbg, lines, line_count);

  return success;
}

static void
gum_enumerate_cu_dies (Dwarf_Debug dbg,
                       gboolean is_info,
                       GumFoundCuDieFunc func,
                       gpointer user_data)
{
  GumCuDieDetails details;
  gboolean carry_on;

  details.dbg = dbg;

  carry_on = TRUE;

  while (TRUE)
  {
    Dwarf_Unsigned next_cu_header_offset;
    const Dwarf_Die no_die = NULL;

    if (dwarf_next_cu_header_d (dbg, is_info, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, &next_cu_header_offset, NULL, NULL) != DW_DLV_OK)
      break;

    if (!carry_on)
      continue;

    if (dwarf_siblingof_b (dbg, no_die, is_info, &details.cu_die, NULL)
        != DW_DLV_OK)
      continue;

    carry_on = func (&details, user_data);

    dwarf_dealloc (dbg, details.cu_die, DW_DLA_DIE);
  }
}

static void
gum_enumerate_dies (Dwarf_Debug dbg,
                    Dwarf_Die die,
                    GumFoundDieFunc func,
                    gpointer user_data)
{
  gum_enumerate_dies_recurse (dbg, die, func, user_data);
}

static gboolean
gum_enumerate_dies_recurse (Dwarf_Debug dbg,
                            Dwarf_Die die,
                            GumFoundDieFunc func,
                            gpointer user_data)
{
  gboolean carry_on;
  GumDieDetails details;
  Dwarf_Die child, cur, sibling;

  details.die = die;
  if (dwarf_tag (die, &details.tag, NULL) != DW_DLV_OK)
    return TRUE;

  details.dbg = dbg;

  carry_on = func (&details, user_data);
  if (!carry_on)
    return FALSE;

  if (dwarf_child (die, &child, NULL) != DW_DLV_OK)
    return TRUE;

  carry_on = gum_enumerate_dies_recurse (dbg, child, func, user_data);
  if (!carry_on)
  {
    dwarf_dealloc (dbg, child, DW_DLA_DIE);
    return FALSE;
  }

  cur = child;

  while (TRUE)
  {
    int status;

    status = dwarf_siblingof (dbg, cur, &sibling, NULL);
    dwarf_dealloc (dbg, cur, DW_DLA_DIE);
    if (status != DW_DLV_OK)
      break;
    cur = sibling;

    carry_on = gum_enumerate_dies_recurse (dbg, cur, func, user_data);
    if (!carry_on)
    {
      dwarf_dealloc (dbg, cur, DW_DLA_DIE);
      break;
    }
  }

  return carry_on;
}

static gboolean
gum_read_die_name (Dwarf_Debug dbg,
                   Dwarf_Die die,
                   gchar ** name)
{
  char * str;

  if (dwarf_diename (die, &str, NULL) != DW_DLV_OK)
    return FALSE;

  *name = g_strdup (str);

  dwarf_dealloc (dbg, str, DW_DLA_STRING);

  return TRUE;
}

static gboolean
gum_read_attribute_location (Dwarf_Debug dbg,
                             Dwarf_Die die,
                             Dwarf_Half id,
                             Dwarf_Addr * address)
{
  gboolean success;
  Dwarf_Attribute attribute;
  Dwarf_Loc_Head_c locations;
  Dwarf_Unsigned count;
  Dwarf_Small lle_value;
  Dwarf_Addr low_pc, high_pc;
  Dwarf_Unsigned loclist_count;
  Dwarf_Locdesc_c loclist;
  Dwarf_Small loclist_source;
  Dwarf_Unsigned expression_offset;
  Dwarf_Unsigned locdesc_offset;
  Dwarf_Small atom;
  Dwarf_Unsigned op1, op2, op3;
  Dwarf_Unsigned offset_for_branch;

  success = FALSE;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    goto invalid_attribute;

  if (dwarf_get_loclist_c (attribute, &locations, &count, NULL) != DW_DLV_OK)
    goto invalid_type;

  if (count != 1)
    goto invalid_locations;

  if (dwarf_get_locdesc_entry_c (locations,
      0,
      &lle_value,
      &low_pc,
      &high_pc,
      &loclist_count,
      &loclist,
      &loclist_source,
      &expression_offset,
      &locdesc_offset,
      NULL) != DW_DLV_OK)
  {
    goto invalid_locations;
  }

  if (lle_value != DW_LLE_offset_pair)
    goto invalid_locations;
  if (loclist_count != 1)
    goto invalid_locations;

  if (dwarf_get_location_op_value_c (loclist,
      0,
      &atom,
      &op1,
      &op2,
      &op3,
      &offset_for_branch,
      NULL) != DW_DLV_OK)
  {
    goto invalid_locations;
  }

  if (atom != DW_OP_addr)
    goto invalid_locations;

  *address = op1;

  success = TRUE;

invalid_locations:
  dwarf_loc_head_c_dealloc (locations);

invalid_type:
  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

invalid_attribute:
  return success;
}

static gboolean
gum_read_attribute_address (Dwarf_Debug dbg,
                            Dwarf_Die die,
                            Dwarf_Half id,
                            Dwarf_Addr * address)
{
  gboolean success;
  Dwarf_Attribute attribute;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    return FALSE;

  success = dwarf_formaddr (attribute, address, NULL) == DW_DLV_OK;

  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return success;
}

static gboolean
gum_read_attribute_offset (Dwarf_Debug dbg,
                           Dwarf_Die die,
                           Dwarf_Half id,
                           Dwarf_Off * offset)
{
  gboolean success;
  Dwarf_Attribute attribute;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    return FALSE;

  success = dwarf_global_formref (attribute, offset, NULL) == DW_DLV_OK;

  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return success;
}

static gboolean
gum_read_attribute_uint (Dwarf_Debug dbg,
                         Dwarf_Die die,
                         Dwarf_Half id,
                         Dwarf_Unsigned * value)
{
  gboolean success;
  Dwarf_Attribute attribute;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    return FALSE;

  success = dwarf_formudata (attribute, value, NULL) == DW_DLV_OK;

  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return success;
}

static gint
gum_compare_pointers (gconstpointer a,
                      gconstpointer b)
{
  return *((gconstpointer *) a) - *((gconstpointer *) b);
}
