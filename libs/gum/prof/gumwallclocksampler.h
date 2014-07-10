/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2009 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_WALLCLOCK_SAMPLER_H__
#define __GUM_WALLCLOCK_SAMPLER_H__

#include "gumsampler.h"

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
