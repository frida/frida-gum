/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MACHO_MAPPER_H__
#define __GUM_MACHO_MAPPER_H__

#include "gumdarwin.h"
#include "gumdarwinmoduleresolver.h"

G_BEGIN_DECLS

#define GUM_MACHO_TYPE_MAPPER (gum_macho_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumMachoMapper, gum_macho_mapper, GUM_MACHO, MAPPER,
                      GObject)

typedef void (* GumMachoMapperConstructor) (void);
typedef void (* GumMachoMapperDestructor) (void);

GUM_API GumMachoMapper * gum_macho_mapper_new_from_file (const gchar * path,
    GumDarwinModuleResolver * resolver, GError ** error);
GUM_API GumMachoMapper * gum_macho_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumDarwinModuleResolver * resolver, GError ** error);

GUM_API gboolean gum_macho_mapper_load (GumMachoMapper * self,
    GError ** error);

GUM_API void gum_macho_mapper_add_apple_parameter (GumMachoMapper * self,
    const gchar * key, const gchar * value);

GUM_API gsize gum_macho_mapper_size (GumMachoMapper * self);
GUM_API gboolean gum_macho_mapper_map (GumMachoMapper * self,
    GumAddress base_address, GError ** error);

GUM_API GumAddress gum_macho_mapper_constructor (GumMachoMapper * self);
GUM_API GumAddress gum_macho_mapper_destructor (GumMachoMapper * self);
GUM_API GumAddress gum_macho_mapper_resolve (GumMachoMapper * self,
    const gchar * symbol);

G_END_DECLS

#endif
