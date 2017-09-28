/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

typedef struct _GumDwarfSymbolDetails GumDwarfSymbolDetails;
typedef struct _GumDwarfSourceDetails GumDwarfSourceDetails;
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

static GumModuleEntry * gum_module_entry_from_address (gpointer address);
static GumModuleEntry * gum_module_entry_from_path_and_base (const gchar * path,
    GumAddress base_address);
static Dwarf_Addr gum_module_entry_virtual_address_to_file (
    GumModuleEntry * self, gpointer address);

static GHashTable * gum_get_function_addresses (void);
static gboolean gum_collect_module_functions (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_collect_cu_die_functions (const GumCuDieDetails * details,
    GumElfModule * module);
static gboolean gum_collect_address_if_function (const GumDieDetails * details,
    GumElfModule * module);

static void gum_symbol_util_ensure_initialized (void);
static void gum_symbol_util_deinitialize (void);

static void gum_on_dwarf_error (Dwarf_Error error, Dwarf_Ptr errarg);

static Dwarf_Die gum_find_cu_die_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Addr address);
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
static gboolean gum_read_attribute_uint (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Unsigned * value);

G_LOCK_DEFINE_STATIC (gum_symbol_util);
static GHashTable * gum_module_entries = NULL;
static GHashTable * gum_function_addresses = NULL;
static GTimer * gum_cache_timer = NULL;

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  gboolean success;
  GumModuleEntry * entry;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;
  GumDwarfSymbolDetails symbol;
  GumDwarfSourceDetails source;

  success = FALSE;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address);
  if (entry == NULL)
    goto entry_not_found;

  file_address = gum_module_entry_virtual_address_to_file (entry, address);

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  if (!gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol))
    goto symbol_not_found;

  if (!gum_find_line_by_virtual_address (entry->dbg, cu_die, file_address,
      symbol.line_number, &source))
    goto line_not_found;

  bzero (details, sizeof (GumDebugSymbolDetails));

  details->address = GUM_ADDRESS (address);
  g_strlcpy (details->module_name, entry->module->name,
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
entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return success;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  GumDwarfSymbolDetails symbol;
  GumModuleEntry * entry;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;

  symbol.name = NULL;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address);
  if (entry == NULL)
    goto entry_not_found;

  file_address = gum_module_entry_virtual_address_to_file (entry, address);

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol);

  dwarf_dealloc (entry->dbg, cu_die, DW_DLA_DIE);

cu_die_not_found:
entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return symbol.name;
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
  GPatternSpec * pspec;
  GHashTableIter iter;
  const gchar * name;
  GArray * addresses;

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));

  pspec = g_pattern_spec_new (str);

  G_LOCK (gum_symbol_util);

  g_hash_table_iter_init (&iter, gum_get_function_addresses ());
  while (g_hash_table_iter_next (&iter, (gpointer *) &name,
      (gpointer *) &addresses))
  {
    if (g_pattern_match_string (pspec, name))
    {
      g_array_append_vals (matches, addresses->data, addresses->len);
    }
  }

  G_UNLOCK (gum_symbol_util);

  g_pattern_spec_free (pspec);

  return matches;
}

static GumModuleEntry *
gum_module_entry_from_address (gpointer address)
{
  Dl_info dl_info;

  if (!dladdr (address, &dl_info))
    return NULL;

  return gum_module_entry_from_path_and_base (dl_info.dli_fname,
      GUM_ADDRESS (dl_info.dli_fbase));
}

static GumModuleEntry *
gum_module_entry_from_path_and_base (const gchar * path,
                                     GumAddress base_address)
{
  GumModuleEntry * entry;
  GumElfModule * module;
  Dwarf_Debug dbg;

  gum_symbol_util_ensure_initialized ();

  entry = g_hash_table_lookup (gum_module_entries, path);
  if (entry != NULL)
    return entry;

  module = gum_elf_module_new_from_memory (path, base_address);
  if (module == NULL)
    goto error;

  if (dwarf_elf_init_b (module->elf, DW_DLC_READ, DW_GROUPNUMBER_ANY,
      gum_on_dwarf_error, NULL, &dbg, NULL) != DW_DLV_OK)
    goto dwarf_error;

  entry = g_slice_new (GumModuleEntry);
  entry->module = module;
  entry->dbg = dbg;
  entry->collected = FALSE;

  g_hash_table_insert (gum_module_entries, g_strdup (path), entry);

  return entry;

dwarf_error:
  {
    g_object_unref (module);
    return NULL;
  }
error:
  {
    return NULL;
  }
}

static Dwarf_Addr
gum_module_entry_virtual_address_to_file (GumModuleEntry * self,
                                          gpointer address)
{
  return self->module->preferred_address +
      (GUM_ADDRESS (address) - self->module->base_address);
}

static void
gum_module_entry_free (GumModuleEntry * entry)
{
  dwarf_finish (entry->dbg, NULL);
  g_object_unref (entry->module);

  g_slice_free (GumModuleEntry, entry);
}

static GHashTable *
gum_get_function_addresses (void)
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

  return gum_function_addresses;
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

  gum_enumerate_cu_dies (entry->dbg, TRUE,
      (GumFoundCuDieFunc) gum_collect_cu_die_functions, entry->module);

  entry->collected = TRUE;

  return TRUE;
}

static gboolean
gum_collect_cu_die_functions (const GumCuDieDetails * details,
                              GumElfModule * module)
{
  gum_enumerate_dies (details->dbg, details->cu_die,
      (GumFoundDieFunc) gum_collect_address_if_function, module);

  return TRUE;
}

static gboolean
gum_collect_address_if_function (const GumDieDetails * details,
                                 GumElfModule * module)
{
  Dwarf_Debug dbg = details->dbg;
  Dwarf_Die die = details->die;
  Dwarf_Addr address;
  gpointer raw_address;
  gchar * name;
  GArray * addresses;

  if (details->tag != DW_TAG_subprogram)
    return TRUE;

  if (!gum_read_attribute_address (dbg, die, DW_AT_low_pc, &address))
    return TRUE;
  raw_address = GSIZE_TO_POINTER (module->base_address +
      (address - module->preferred_address));

  if (!gum_read_die_name (dbg, die, &name))
    return TRUE;

  addresses = g_hash_table_lookup (gum_function_addresses, name);
  if (addresses == NULL)
  {
    addresses = g_array_new (FALSE, FALSE, sizeof (gpointer));
    g_hash_table_insert (gum_function_addresses, name, addresses);
  }
  else
  {
    g_free (name);
  }

  g_array_append_val (addresses, raw_address);

  return TRUE;
}

static void
gum_function_addresses_free (GArray * addresses)
{
  g_array_free (addresses, TRUE);
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

  _gum_register_destructor (gum_symbol_util_deinitialize);
}

static void
gum_symbol_util_deinitialize (void)
{
  g_clear_pointer (&gum_cache_timer, g_timer_destroy);

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
  int status;
  Dwarf_Arange * aranges;
  Dwarf_Signed arange_count, arange_index;

  status = dwarf_get_aranges (dbg, &aranges, &arange_count, NULL);
  if (status != DW_DLV_OK)
    return NULL;

  result = NULL;

  for (arange_index = 0; arange_index != arange_count; arange_index++)
  {
    Dwarf_Arange arange = aranges[arange_index];

    if (result == NULL)
    {
      Dwarf_Addr start;
      Dwarf_Unsigned length;
      Dwarf_Off cu_die_offset;

      status = dwarf_get_arange_info_b (arange, NULL, NULL, &start, &length,
          &cu_die_offset, NULL);
      if (status == DW_DLV_OK && address >= start && address < start + length)
      {
        dwarf_offdie (dbg, cu_die_offset, &result, NULL);
      }
    }

    dwarf_dealloc (dbg, arange, DW_DLA_ARANGE);
  }

  dwarf_dealloc (dbg, aranges, DW_DLA_LIST);

  return result;
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
