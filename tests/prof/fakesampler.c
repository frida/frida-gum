/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
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

#include "fakesampler.h"

static void gum_fake_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_fake_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumFakeSampler,
                        gum_fake_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                                               gum_fake_sampler_iface_init));

static void
gum_fake_sampler_class_init (GumFakeSamplerClass * klass)
{
}

static void
gum_fake_sampler_iface_init (gpointer g_iface,
                                gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  iface->sample = gum_fake_sampler_sample;
}

static void
gum_fake_sampler_init (GumFakeSampler * self)
{
  self->now = 0;
}

GumSampler *
gum_fake_sampler_new (void)
{
  GumFakeSampler * sampler;

  sampler = g_object_new (GUM_TYPE_FAKE_SAMPLER, NULL);

  return GUM_SAMPLER (sampler);
}

void
gum_fake_sampler_advance (GumFakeSampler * self,
                          GumSample delta)
{
  self->now += delta;
}

static GumSample
gum_fake_sampler_sample (GumSampler * sampler)
{
  GumFakeSampler * self = GUM_FAKE_SAMPLER (sampler);
  return self->now;
}
