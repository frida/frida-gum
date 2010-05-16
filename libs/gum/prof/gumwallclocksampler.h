/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2009 Christian Berentsen <christian.berentsen@tandberg.com>
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

#ifndef __GUM_WALLCLOCK_SAMPLER_H__
#define __GUM_WALLCLOCK_SAMPLER_H__

#include <glib-object.h>
#include <gum/prof/gumsampler.h>

#define GUM_TYPE_WALLCLOCK_SAMPLER (gum_wallclock_sampler_get_type ())
#define GUM_WALLCLOCK_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_WALLCLOCK_SAMPLER, GumWallclockSampler))
#define GUM_WALLCLOCK_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_WALLCLOCK_SAMPLER, GumWallclockSamplerClass))
#define GUM_IS_WALLCLOCK_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_WALLCLOCK_SAMPLER))
#define GUM_IS_WALLCLOCK_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_WALLCLOCK_SAMPLER))
#define GUM_WALLCLOCK_SAMPLER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_WALLCLOCK_SAMPLER, GumWallclockSamplerClass))

typedef struct _GumWallclockSampler GumWallclockSampler;
typedef struct _GumWallclockSamplerClass GumWallclockSamplerClass;

struct _GumWallclockSampler
{
  GObject parent;
};

struct _GumWallclockSamplerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_wallclock_sampler_get_type (void) G_GNUC_CONST;

GUM_API GumSampler * gum_wallclock_sampler_new (void);

G_END_DECLS

#endif
