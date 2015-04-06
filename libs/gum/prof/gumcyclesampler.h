/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CYCLE_SAMPLER_H__
#define __GUM_CYCLE_SAMPLER_H__

#include "gumsampler.h"

#define GUM_TYPE_CYCLE_SAMPLER (gum_cycle_sampler_get_type ())
#define GUM_CYCLE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_CYCLE_SAMPLER, GumCycleSampler))
#define GUM_CYCLE_SAMPLER_CAST(obj) ((GumCycleSampler *) (obj))
#define GUM_CYCLE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_CYCLE_SAMPLER, GumCycleSamplerClass))
#define GUM_IS_CYCLE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_CYCLE_SAMPLER))
#define GUM_IS_CYCLE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_CYCLE_SAMPLER))
#define GUM_CYCLE_SAMPLER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_CYCLE_SAMPLER, GumCycleSamplerClass))

typedef struct _GumCycleSampler GumCycleSampler;
typedef struct _GumCycleSamplerClass GumCycleSamplerClass;
typedef struct _GumCycleSamplerPrivate GumCycleSamplerPrivate;

struct _GumCycleSampler
{
  GObject parent;

  GumCycleSamplerPrivate * priv;
};

struct _GumCycleSamplerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_cycle_sampler_get_type (void) G_GNUC_CONST;

GUM_API GumSampler * gum_cycle_sampler_new (void);

GUM_API gboolean gum_cycle_sampler_is_available (GumCycleSampler * self);

G_END_DECLS

#endif
