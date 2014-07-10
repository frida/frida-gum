/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_BUSY_CYCLE_SAMPLER_H__
#define __GUM_BUSY_CYCLE_SAMPLER_H__

#include "gumsampler.h"

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
