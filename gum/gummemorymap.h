/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
