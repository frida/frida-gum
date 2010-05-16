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

#ifndef __BUSY_CYCLE_SAMPLER_H__
#define __BUSY_CYCLE_SAMPLER_H__

#include <glib-object.h>
#include <gum/prof/gumsampler.h>

#define GUM_TYPE_BUSY_CYCLE_SAMPLER (gum_busy_cycle_sampler_get_type ())
#define GUM_BUSY_CYCLE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_BUSY_CYCLE_SAMPLER, GumBusyCycleSampler))
#define GUM_BUSY_CYCLE_SAMPLER_CAST(obj) ((GumBusyCycleSampler *) (obj))
#define GUM_BUSY_CYCLE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_BUSY_CYCLE_SAMPLER, GumBusyCycleSamplerClass))
#define GUM_IS_BUSY_CYCLE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_BUSY_CYCLE_SAMPLER))
#define GUM_IS_BUSY_CYCLE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_BUSY_CYCLE_SAMPLER))
#define GUM_BUSY_CYCLE_SAMPLER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_BUSY_CYCLE_SAMPLER, GumBusyCycleSamplerClass))

typedef struct _GumBusyCycleSampler GumBusyCycleSampler;
typedef struct _GumBusyCycleSamplerClass GumBusyCycleSamplerClass;

typedef struct _GumBusyCycleSamplerPrivate GumBusyCycleSamplerPrivate;

struct _GumBusyCycleSampler
{
  GObject parent;

  GumBusyCycleSamplerPrivate * priv;
};

struct _GumBusyCycleSamplerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_busy_cycle_sampler_get_type (void) G_GNUC_CONST;

GUM_API GumSampler * gum_busy_cycle_sampler_new (void);

GUM_API gboolean gum_busy_cycle_sampler_is_available (
    GumBusyCycleSampler * self);

G_END_DECLS

#endif
