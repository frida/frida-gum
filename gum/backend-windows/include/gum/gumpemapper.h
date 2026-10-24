/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PE_MAPPER_H__
#define __GUM_PE_MAPPER_H__

#include "gummoduleresolver.h"
#include "gumprocessmemory.h"

G_BEGIN_DECLS

#define GUM_TYPE_PE_MAPPER (gum_pe_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumPeMapper, gum_pe_mapper, GUM, PE_MAPPER, GObject)

GUM_API GumPeMapper * gum_pe_mapper_new_from_file (const gchar * path,
    GumModuleResolver * resolver, GError ** error);
GUM_API GumPeMapper * gum_pe_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumModuleResolver * resolver, GError ** error);

GUM_API gboolean gum_pe_mapper_load (GumPeMapper * self, GError ** error);
GUM_API void gum_pe_mapper_set_target (GumPeMapper * self,
    GumProcessMemory * target);

GUM_API gsize gum_pe_mapper_size (GumPeMapper * self);
GUM_API gboolean gum_pe_mapper_map (GumPeMapper * self,
    GumAddress base_address, GError ** error);

GUM_API GumAddress gum_pe_mapper_constructor (GumPeMapper * self);
GUM_API GumAddress gum_pe_mapper_destructor (GumPeMapper * self);
GUM_API GumAddress gum_pe_mapper_resolve (GumPeMapper * self,
    const gchar * symbol);

G_END_DECLS

#endif
