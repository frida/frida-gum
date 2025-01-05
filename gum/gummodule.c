/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule.h"

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

static gboolean gum_store_address_if_name_matches (
    const GumSymbolDetails * details, gpointer user_data);

G_DEFINE_INTERFACE (GumModule, gum_module, G_TYPE_OBJECT)

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
  GumResolveSymbolContext ctx;

  iface = GUM_MODULE_GET_IFACE (self);

  if (iface->find_symbol_by_name != NULL)
    return iface->find_symbol_by_name (self, symbol_name);

  ctx.name = symbol_name;
  ctx.result = 0;

  gum_module_enumerate_symbols (self, gum_store_address_if_name_matches, &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}
