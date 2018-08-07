/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2009 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumwallclocksampler.h"

struct _GumWallclockSampler
{
  GObject parent;
};

static void gum_wallclock_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_wallclock_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumWallclockSampler,
                        gum_wallclock_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                            gum_wallclock_sampler_iface_init))

static void
gum_wallclock_sampler_class_init (GumWallclockSamplerClass * klass)
{
}

static void
gum_wallclock_sampler_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumSamplerInterface * iface = g_iface;

  iface->sample = gum_wallclock_sampler_sample;
}

static void
gum_wallclock_sampler_init (GumWallclockSampler * self)
{
}

GumSampler *
gum_wallclock_sampler_new (void)
{
  return g_object_new (GUM_TYPE_WALLCLOCK_SAMPLER, NULL);
}

static GumSample
gum_wallclock_sampler_sample (GumSampler * sampler)
{
  return g_get_monotonic_time ();
}
