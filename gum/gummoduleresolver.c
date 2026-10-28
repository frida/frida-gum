/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleresolver.h"

static gboolean gum_module_resolver_real_find_dynamic_symbol (
    GumModuleResolver * self, const gchar * symbol,
    GumDynamicSymbolDetails * details);

G_DEFINE_INTERFACE (GumModuleResolver, gum_module_resolver, G_TYPE_OBJECT)

static void
gum_module_resolver_default_init (GumModuleResolverInterface * iface)
{
  iface->find_dynamic_symbol = gum_module_resolver_real_find_dynamic_symbol;
}

GumModule *
gum_module_resolver_find_module_by_name (GumModuleResolver * self,
                                         const gchar * name)
{
  return GUM_MODULE_RESOLVER_GET_IFACE (self)->find_module_by_name (self, name);
}

GumAddress
gum_module_resolver_find_dynamic_address (GumModuleResolver * self,
                                          const gchar * symbol)
{
  return GUM_MODULE_RESOLVER_GET_IFACE (self)->find_dynamic_address (self,
      symbol);
}

gboolean
gum_module_resolver_find_dynamic_symbol (GumModuleResolver * self,
                                         const gchar * symbol,
                                         GumDynamicSymbolDetails * details)
{
  return GUM_MODULE_RESOLVER_GET_IFACE (self)->find_dynamic_symbol (self,
      symbol, details);
}

static gboolean
gum_module_resolver_real_find_dynamic_symbol (
    GumModuleResolver * self,
    const gchar * symbol,
    GumDynamicSymbolDetails * details)
{
  details->address = gum_module_resolver_find_dynamic_address (self, symbol);
  details->indirect = FALSE;

  return details->address != 0;
}
