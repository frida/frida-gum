/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MAPPER_H__
#define __GUM_MAPPER_H__

#include <gum/gummoduleresolver.h>
#include <gum/gumprocessmemory.h>

G_BEGIN_DECLS

#define GUM_TYPE_MAPPER (gum_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumMapper, gum_mapper, GUM, MAPPER, GObject)

typedef void (* GumMapperConstructor) (void);
typedef void (* GumMapperDestructor) (void);

GUM_API GumMapper * gum_mapper_new_from_file (const gchar * path,
    GumModuleResolver * resolver, GError ** error);
GUM_API GumMapper * gum_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumModuleResolver * resolver, GError ** error);

GUM_API gboolean gum_mapper_load (GumMapper * self, GError ** error);
GUM_API void gum_mapper_set_target (GumMapper * self,
    GumProcessMemory * target);

GUM_API void gum_mapper_add_apple_parameter (GumMapper * self,
    const gchar * key, const gchar * value);

GUM_API gsize gum_mapper_size (GumMapper * self);
GUM_API gboolean gum_mapper_map (GumMapper * self, GumAddress base_address,
    GError ** error);

GUM_API GumAddress gum_mapper_constructor (GumMapper * self);
GUM_API GumAddress gum_mapper_destructor (GumMapper * self);
GUM_API GumAddress gum_mapper_resolve (GumMapper * self, const gchar * symbol);

G_END_DECLS

#endif
