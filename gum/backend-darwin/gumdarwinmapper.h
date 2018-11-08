/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_MAPPER_H__
#define __GUM_DARWIN_MAPPER_H__

#include "gumdarwin.h"
#include "gumdarwinmoduleresolver.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GUM_DARWIN_TYPE_MAPPER (gum_darwin_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumDarwinMapper, gum_darwin_mapper, GUM_DARWIN, MAPPER,
    GObject)

typedef void (* GumDarwinMapperConstructor) (void);
typedef void (* GumDarwinMapperDestructor) (void);

GUM_API GumDarwinMapper * gum_darwin_mapper_new_from_file (const gchar * path,
    GumDarwinModuleResolver * resolver);
GUM_API GumDarwinMapper * gum_darwin_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumDarwinModuleResolver * resolver);

GUM_API gsize gum_darwin_mapper_size (GumDarwinMapper * self);
GUM_API void gum_darwin_mapper_map (GumDarwinMapper * self,
    GumAddress base_address);

GUM_API GumAddress gum_darwin_mapper_constructor (GumDarwinMapper * self);
GUM_API GumAddress gum_darwin_mapper_destructor (GumDarwinMapper * self);
GUM_API GumAddress gum_darwin_mapper_resolve (GumDarwinMapper * self,
    const gchar * symbol);

G_END_DECLS

#endif
