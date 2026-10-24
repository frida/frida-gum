/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ELF_MAPPER_H__
#define __GUM_ELF_MAPPER_H__

#include <gum/gummoduleresolver.h>
#include <gum/gumprocessmemory.h>

G_BEGIN_DECLS

#define GUM_TYPE_ELF_MAPPER (gum_elf_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumElfMapper, gum_elf_mapper, GUM, ELF_MAPPER, GObject)

GUM_API GumElfMapper * gum_elf_mapper_new_from_file (const gchar * path,
    GumModuleResolver * resolver, GError ** error);
GUM_API GumElfMapper * gum_elf_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumModuleResolver * resolver, GError ** error);

GUM_API gboolean gum_elf_mapper_load (GumElfMapper * self, GError ** error);
GUM_API void gum_elf_mapper_set_target (GumElfMapper * self,
    GumProcessMemory * target);

GUM_API gsize gum_elf_mapper_size (GumElfMapper * self);
GUM_API gboolean gum_elf_mapper_map (GumElfMapper * self,
    GumAddress base_address, GError ** error);

GUM_API GumAddress gum_elf_mapper_constructor (GumElfMapper * self);
GUM_API GumAddress gum_elf_mapper_destructor (GumElfMapper * self);
GUM_API GumAddress gum_elf_mapper_resolve (GumElfMapper * self,
    const gchar * symbol);

G_END_DECLS

#endif
