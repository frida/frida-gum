/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ELF_MODULE_RESOLVER_H__
#define __GUM_ELF_MODULE_RESOLVER_H__

#include <gum/gumelfmodule.h>
#include <gum/gummoduleresolver.h>

G_BEGIN_DECLS

#define GUM_TYPE_ELF_MODULE_RESOLVER (gum_elf_module_resolver_get_type ())
G_DECLARE_FINAL_TYPE (GumElfModuleResolver, gum_elf_module_resolver, GUM,
                      ELF_MODULE_RESOLVER, GObject)

GUM_API GumElfModuleResolver * gum_elf_module_resolver_new (void);

GUM_API void gum_elf_module_resolver_add_module (GumElfModuleResolver * self,
    GumElfModule * module, GumAddress base_address);

G_END_DECLS

#endif
