/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUM_MEMORY_MAP_H__
#define __GUM_MEMORY_MAP_H__

#include <glib-object.h>
#include <gum/gummemory.h>

#define GUM_TYPE_MEMORY_MAP (gum_memory_map_get_type ())
#define GUM_MEMORY_MAP(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_MEMORY_MAP, GumMemoryMap))
#define GUM_MEMORY_MAP_CAST(obj) ((GumMemoryMap *) (obj))
#define GUM_MEMORY_MAP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_MEMORY_MAP, GumMemoryMapClass))
#define GUM_IS_MEMORY_MAP(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_MEMORY_MAP))
#define GUM_IS_MEMORY_MAP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_MEMORY_MAP))
#define GUM_MEMORY_MAP_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_MEMORY_MAP, GumMemoryMapClass))

typedef struct _GumMemoryMap GumMemoryMap;
typedef struct _GumMemoryMapClass GumMemoryMapClass;

typedef struct _GumMemoryMapPrivate GumMemoryMapPrivate;

struct _GumMemoryMap
{
  GObject parent;

  GumMemoryMapPrivate * priv;
};

struct _GumMemoryMapClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_memory_map_get_type (void) G_GNUC_CONST;

GUM_API GumMemoryMap * gum_memory_map_new (GumPageProtection prot);

GUM_API gboolean gum_memory_map_contains (GumMemoryMap * self,
    const GumMemoryRange * range);

GUM_API void gum_memory_map_update (GumMemoryMap * self);

G_END_DECLS

#endif
