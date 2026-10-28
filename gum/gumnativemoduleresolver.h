/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_NATIVE_MODULE_RESOLVER_H__
#define __GUM_NATIVE_MODULE_RESOLVER_H__

#include <gum/gummoduleresolver.h>

G_BEGIN_DECLS

#define GUM_TYPE_NATIVE_MODULE_RESOLVER \
    (gum_native_module_resolver_get_type ())
G_DECLARE_FINAL_TYPE (GumNativeModuleResolver, gum_native_module_resolver, GUM,
                      NATIVE_MODULE_RESOLVER, GObject)

typedef GumAddress (* GumNativeModuleResolverLookupFunc) (const gchar * symbol,
    gpointer user_data);

GUM_API GumNativeModuleResolver * gum_native_module_resolver_new (void);

GUM_API void gum_native_module_resolver_set_dynamic_lookup_handler (
    GumNativeModuleResolver * self, GumNativeModuleResolverLookupFunc func,
    gpointer data, GDestroyNotify data_destroy);

G_END_DECLS

#endif
