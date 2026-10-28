/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_WINDOWS_MODULE_RESOLVER_H__
#define __GUM_WINDOWS_MODULE_RESOLVER_H__

#include <gum/gummoduleresolver.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

G_BEGIN_DECLS

#define GUM_WINDOWS_TYPE_MODULE_RESOLVER \
    (gum_windows_module_resolver_get_type ())
G_DECLARE_FINAL_TYPE (GumWindowsModuleResolver, gum_windows_module_resolver,
                      GUM_WINDOWS, MODULE_RESOLVER, GObject)

GUM_API GumWindowsModuleResolver * gum_windows_module_resolver_new (
    HANDLE process);

G_END_DECLS

#endif
