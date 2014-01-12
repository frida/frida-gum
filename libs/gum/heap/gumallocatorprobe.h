/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
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

#ifndef __GUM_ALLOCATOR_PROBE_H__
#define __GUM_ALLOCATOR_PROBE_H__

#include "gumallocationtracker.h"
#include "gumheapapi.h"

#define GUM_TYPE_ALLOCATOR_PROBE (gum_allocator_probe_get_type ())
#define GUM_ALLOCATOR_PROBE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_ALLOCATOR_PROBE, GumAllocatorProbe))
#define GUM_ALLOCATOR_PROBE_CAST(obj) ((GumAllocatorProbe *) (obj))
#define GUM_ALLOCATOR_PROBE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_ALLOCATOR_PROBE, GumAllocatorProbeClass))
#define GUM_IS_ALLOCATOR_PROBE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_ALLOCATOR_PROBE))
#define GUM_IS_ALLOCATOR_PROBE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_ALLOCATOR_PROBE))
#define GUM_ALLOCATOR_PROBE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_ALLOCATOR_PROBE, GumAllocatorProbeClass))

typedef struct _GumAllocatorProbe GumAllocatorProbe;
typedef struct _GumAllocatorProbeClass GumAllocatorProbeClass;

typedef struct _GumAllocatorProbePrivate GumAllocatorProbePrivate;

struct _GumAllocatorProbe
{
  GObject parent;

  GumAllocatorProbePrivate * priv;
};

struct _GumAllocatorProbeClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_allocator_probe_get_type (void) G_GNUC_CONST;

GUM_API GumAllocatorProbe * gum_allocator_probe_new (void);

GUM_API void gum_allocator_probe_attach (GumAllocatorProbe * self);
GUM_API void gum_allocator_probe_attach_to_apis (GumAllocatorProbe * self,
    const GumHeapApiList * apis);
GUM_API void gum_allocator_probe_detach (GumAllocatorProbe * self);

GUM_API void gum_allocator_probe_suppress (GumAllocatorProbe * self,
    gpointer function_address);

G_END_DECLS

#endif
