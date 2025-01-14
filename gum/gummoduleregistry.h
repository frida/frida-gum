/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_REGISTRY_H__
#define __GUM_MODULE_REGISTRY_H__

#include <gum/gummodule.h>

G_BEGIN_DECLS

#define GUM_TYPE_MODULE_REGISTRY (gum_module_registry_get_type ())
G_DECLARE_FINAL_TYPE (GumModuleRegistry, gum_module_registry, GUM,
                      MODULE_REGISTRY, GObject)

GUM_API GumModuleRegistry * gum_module_registry_obtain (void);

G_END_DECLS

#endif
