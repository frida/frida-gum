/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_RESOLVER_H__
#define __GUM_MODULE_RESOLVER_H__

#include <gum/gummodule.h>

G_BEGIN_DECLS

#define GUM_TYPE_MODULE_RESOLVER (gum_module_resolver_get_type ())
G_DECLARE_INTERFACE (GumModuleResolver, gum_module_resolver, GUM,
                     MODULE_RESOLVER, GObject)

struct _GumModuleResolverInterface
{
  GTypeInterface parent;

  GumModule * (* find_module_by_name) (GumModuleResolver * self,
      const gchar * name);
  GumAddress (* find_dynamic_address) (GumModuleResolver * self,
      const gchar * symbol);
};

GUM_API GumModule * gum_module_resolver_find_module_by_name (
    GumModuleResolver * self, const gchar * name);
GUM_API GumAddress gum_module_resolver_find_dynamic_address (
    GumModuleResolver * self, const gchar * symbol);

G_END_DECLS

#endif
