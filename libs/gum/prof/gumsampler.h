/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#ifndef __GUM_SAMPLER_H__
#define __GUM_SAMPLER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_SAMPLER (gum_sampler_get_type ())
#define GUM_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SAMPLER, GumSampler))
#define GUM_SAMPLER_CAST(obj) ((GumSampler *) (obj))
#define GUM_IS_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SAMPLER))
#define GUM_SAMPLER_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_SAMPLER, GumSamplerIface))

typedef struct _GumSampler GumSampler;
typedef struct _GumSamplerIface GumSamplerIface;

typedef guint64 GumSample;

struct _GumSamplerIface
{
  GTypeInterface parent;

  GumSample (*sample) (GumSampler * self);
};

G_BEGIN_DECLS

GType gum_sampler_get_type (void);

GUM_API GumSample gum_sampler_sample (GumSampler * self);

G_END_DECLS

#endif
