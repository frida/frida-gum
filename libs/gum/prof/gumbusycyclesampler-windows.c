/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumbusycyclesampler.h"

#define _WIN32_LEAN_AND_MEAN
#ifdef _WIN32_WINNT
# undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tchar.h>

typedef BOOL (WINAPI * QueryThreadCycleTimeFunc) (HANDLE ThreadHandle,
    PULONG64 CycleTime);

struct _GumBusyCycleSamplerPrivate
{
  QueryThreadCycleTimeFunc query_thread_cycle_time;
};

static void gum_busy_cycle_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumSample gum_busy_cycle_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumBusyCycleSampler,
                        gum_busy_cycle_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                                               gum_busy_cycle_sampler_iface_init));

static void
gum_busy_cycle_sampler_class_init (GumBusyCycleSamplerClass * klass)
{
  g_type_class_add_private (klass, sizeof (GumBusyCycleSamplerPrivate));
}

static void
gum_busy_cycle_sampler_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  (void) iface_data;

  iface->sample = gum_busy_cycle_sampler_sample;
}

static void
gum_busy_cycle_sampler_init (GumBusyCycleSampler * self)
{
  HMODULE mod;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_BUSY_CYCLE_SAMPLER,
      GumBusyCycleSamplerPrivate);

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert (mod != NULL);

  self->priv->query_thread_cycle_time =
      (QueryThreadCycleTimeFunc) GetProcAddress (mod, "QueryThreadCycleTime");
}

GumSampler *
gum_busy_cycle_sampler_new (void)
{
  GumBusyCycleSampler * sampler;

  sampler = g_object_new (GUM_TYPE_BUSY_CYCLE_SAMPLER, NULL);

  return GUM_SAMPLER (sampler);
}

gboolean
gum_busy_cycle_sampler_is_available (GumBusyCycleSampler * self)
{
  return (self->priv->query_thread_cycle_time != NULL);
}

static GumSample
gum_busy_cycle_sampler_sample (GumSampler * sampler)
{
  GumBusyCycleSamplerPrivate * priv = GUM_BUSY_CYCLE_SAMPLER_CAST (sampler)->priv;
  GumSample result = 0;

  priv->query_thread_cycle_time (GetCurrentThread (), &result);

  return result;
}
