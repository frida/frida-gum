/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __FAKE_SAMPLER_H__
#define __FAKE_SAMPLER_H__

#include <glib-object.h>
#include <gum/prof/gumsampler.h>

#define GUM_TYPE_FAKE_SAMPLER (gum_fake_sampler_get_type ())
#define GUM_FAKE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_FAKE_SAMPLER, GumFakeSampler))
#define GUM_FAKE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_FAKE_SAMPLER, GumFakeSamplerClass))
#define GUM_IS_FAKE_SAMPLER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_FAKE_SAMPLER))
#define GUM_IS_FAKE_SAMPLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_FAKE_SAMPLER))
#define GUM_FAKE_SAMPLER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_FAKE_SAMPLER, GumFakeSamplerClass))

typedef struct _GumFakeSampler GumFakeSampler;
typedef struct _GumFakeSamplerClass GumFakeSamplerClass;

struct _GumFakeSampler
{
  GObject parent;

  GumSample now;
};

struct _GumFakeSamplerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_fake_sampler_get_type (void) G_GNUC_CONST;

GumSampler * gum_fake_sampler_new (void);

void gum_fake_sampler_advance (GumFakeSampler * self, GumSample delta);

G_END_DECLS

#endif
