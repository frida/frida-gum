/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2009 Christian Berentsen <jc.berentsen@gmail.com>
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

#include "gumwallclocksampler.h"

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static void gum_wallclock_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_wallclock_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumWallclockSampler,
                        gum_wallclock_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                                               gum_wallclock_sampler_iface_init));

static void
gum_wallclock_sampler_class_init (GumWallclockSamplerClass * klass)
{
  (void) klass;
}

static void
gum_wallclock_sampler_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  (void) iface_data;

  iface->sample = gum_wallclock_sampler_sample;
}

static void
gum_wallclock_sampler_init (GumWallclockSampler * self)
{
  (void) self;
}

GumSampler *
gum_wallclock_sampler_new (void)
{
  return GUM_SAMPLER (g_object_new (GUM_TYPE_WALLCLOCK_SAMPLER, NULL));
}

static GumSample
gum_wallclock_sampler_sample (GumSampler * sampler)
{
#ifdef G_OS_WIN32
  (void) sampler;

  return GetTickCount ();
#else
  GTimeVal tv;

  (void) sampler;

  g_get_current_time (&tv);

  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
#endif
}
