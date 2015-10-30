/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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

  GumSample (* sample) (GumSampler * self);
};

G_BEGIN_DECLS

GType gum_sampler_get_type (void);

GUM_API GumSample gum_sampler_sample (GumSampler * self);

G_END_DECLS

#endif
