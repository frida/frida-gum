/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_MAPPER_H__
#define __GUM_DARWIN_MAPPER_H__

#include "gumdarwin.h"
#include "gumdefs.h"

G_BEGIN_DECLS

typedef struct _GumDarwinMapper GumDarwinMapper;

typedef void (* GumDarwinMapperConstructor) (void);
typedef void (* GumDarwinMapperDestructor) (void);

GumDarwinMapper * gum_darwin_mapper_new (const gchar * name, mach_port_t task,
    GumCpuType cpu_type);
void gum_darwin_mapper_free (GumDarwinMapper * mapper);

gsize gum_darwin_mapper_size (GumDarwinMapper * self);
void gum_darwin_mapper_map (GumDarwinMapper * self, GumAddress base_address);

GumAddress gum_darwin_mapper_constructor (GumDarwinMapper * self);
GumAddress gum_darwin_mapper_destructor (GumDarwinMapper * self);
GumAddress gum_darwin_mapper_resolve (GumDarwinMapper * self,
    const gchar * symbol);

G_END_DECLS

#endif
