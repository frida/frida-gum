/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "fakebacktracer.h"
#include <string.h>

static void gum_fake_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_fake_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumFakeBacktracer,
                        gum_fake_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_fake_backtracer_iface_init));

static void
gum_fake_backtracer_class_init (GumFakeBacktracerClass * klass)
{
}

static void
gum_fake_backtracer_iface_init (gpointer g_iface,
                                gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_fake_backtracer_generate;
}

static void
gum_fake_backtracer_init (GumFakeBacktracer * self)
{
}

GumBacktracer *
gum_fake_backtracer_new (const GumReturnAddress * ret_addrs,
                         guint num_ret_addrs)
{
  GumFakeBacktracer * backtracer;

  backtracer = g_object_new (GUM_TYPE_FAKE_BACKTRACER, NULL);
  backtracer->ret_addrs = ret_addrs;
  backtracer->num_ret_addrs = num_ret_addrs;

  return GUM_BACKTRACER (backtracer);
}

static void
gum_fake_backtracer_generate (GumBacktracer * backtracer,
                              const GumCpuContext * cpu_context,
                              GumReturnAddressArray * return_addresses)
{
  GumFakeBacktracer * self = GUM_FAKE_BACKTRACER (backtracer);

  memcpy (return_addresses->items, self->ret_addrs, self->num_ret_addrs *
      sizeof (GumReturnAddress));
  return_addresses->len = self->num_ret_addrs;
}
