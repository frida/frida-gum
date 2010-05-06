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

#include "gumcyclesampler.h"

static void gum_cycle_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_cycle_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumCycleSampler,
                        gum_cycle_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                                               gum_cycle_sampler_iface_init));

static void
gum_cycle_sampler_class_init (GumCycleSamplerClass * klass)
{
}

static void
gum_cycle_sampler_iface_init (gpointer g_iface,
                                gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  iface->sample = gum_cycle_sampler_sample;
}

static void
gum_cycle_sampler_init (GumCycleSampler * self)
{
}

GumSampler *
gum_cycle_sampler_new (void)
{
  GumCycleSampler * sampler;

  sampler = g_object_new (GUM_TYPE_CYCLE_SAMPLER, NULL);

  return GUM_SAMPLER (sampler);
}

static GumSample
gum_cycle_sampler_sample (GumSampler * sampler)
{
#ifdef _MSC_VER
  GumSample result = 0;

#ifndef _WIN64
  __asm
  {
    /* flush pipeline */
    xor eax, eax;
    cpuid;

    /* read it out */
    rdtsc;
    mov dword ptr [result + 0], eax;
    mov dword ptr [result + 4], edx;
  }
#endif

#else
  register GumSample result asm ("eax");
  asm volatile (".byte 0x0f, 0x31" : : : "eax", "edx");
#endif

  return result;
}
