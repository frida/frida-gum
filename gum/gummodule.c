/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule.h"

#include <string.h>

typedef struct _GumSymbolEntry GumSymbolEntry;

struct _GumSymbolEntry
{
  const gchar * name;
  GumAddress address;
};

static gboolean gum_store_symbol (const GumSymbolDetails * details,
    gpointer user_data);
static gint gum_symbol_entry_compare (const GumSymbolEntry * lhs,
    const GumSymbolEntry * rhs);

G_DEFINE_INTERFACE (GumModule, gum_module, G_TYPE_OBJECT)

G_LOCK_DEFINE_STATIC (gum_module_symbol_cache);

static void
gum_module_default_init (GumModuleInterface * iface)
{
}

const gchar *
gum_module_get_name (GumModule * self)
{
  return GUM_MODULE_GET_IFACE (self)->get_name (self);
}

const gchar *
gum_module_get_path (GumModule * self)
{
  return GUM_MODULE_GET_IFACE (self)->get_path (self);
}

const GumMemoryRange *
gum_module_get_range (GumModule * self)
{
  return GUM_MODULE_GET_IFACE (self)->get_range (self);
}

void
gum_module_ensure_initialized (GumModule * self)
{
  GUM_MODULE_GET_IFACE (self)->ensure_initialized (self);
}

void
gum_module_enumerate_imports (GumModule * self,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_imports (self, func, user_data);
}

void
gum_module_enumerate_exports (GumModule * self,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_exports (self, func, user_data);
}

void
gum_module_enumerate_symbols (GumModule * self,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_symbols (self, func, user_data);
}

void
gum_module_enumerate_ranges (GumModule * self,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_ranges (self, prot, func, user_data);
}

void
gum_module_enumerate_sections (GumModule * self,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_sections (self, func, user_data);
}

void
gum_module_enumerate_dependencies (GumModule * self,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
  GUM_MODULE_GET_IFACE (self)->enumerate_dependencies (self, func, user_data);
}

GumAddress
gum_module_find_export_by_name (GumModule * self,
                                const gchar * symbol_name)
{
  return GUM_MODULE_GET_IFACE (self)->find_export_by_name (self, symbol_name);
}

GumAddress
gum_module_find_symbol_by_name (GumModule * self,
                                const gchar * symbol_name)
{
  GumModuleInterface * iface;
  GArray * cache;
  GumSymbolEntry needle;
  guint matched_index;

  iface = GUM_MODULE_GET_IFACE (self);

  if (iface->find_symbol_by_name != NULL)
    return iface->find_symbol_by_name (self, symbol_name);

  G_LOCK (gum_module_symbol_cache);

  cache = g_object_get_data (G_OBJECT (self), "symbol-cache");
  if (cache == NULL)
  {
    cache = g_array_new (FALSE, FALSE, sizeof (GumSymbolEntry));
    gum_module_enumerate_symbols (self, gum_store_symbol, cache);
    g_array_sort (cache, (GCompareFunc) gum_symbol_entry_compare);
    g_object_set_data_full (G_OBJECT (self), "symbol-cache", cache,
        (GDestroyNotify) g_array_unref);
  }

  G_UNLOCK (gum_module_symbol_cache);

  needle.name = symbol_name;
  needle.address = 0;

  if (!g_array_binary_search (cache, &needle,
        (GCompareFunc) gum_symbol_entry_compare, &matched_index))
  {
    return 0;
  }

  return g_array_index (cache, GumSymbolEntry, matched_index).address;
}

static gboolean
gum_store_symbol (const GumSymbolDetails * details,
                  gpointer user_data)
{
  GArray * cache = user_data;
  GumSymbolEntry entry;

  /*
   * Implementations guarantee that the lifetime of this string is at least that
   * of the module.
   */
  entry.name = details->name;
  entry.address = details->address;
  g_array_append_val (cache, entry);

  return TRUE;
}

static gint
gum_symbol_entry_compare (const GumSymbolEntry * lhs,
                          const GumSymbolEntry * rhs)
{
  return strcmp (lhs->name, rhs->name);
}
