/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include <execinfo.h>
#include <string.h>
#include "gumgnubacktracer.h"

static void gum_gnu_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_gnu_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumGnuBacktracer,
                        gum_gnu_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_gnu_backtracer_iface_init));

static void
gum_gnu_backtracer_class_init (GumGnuBacktracerClass * klass)
{
}

static void
gum_gnu_backtracer_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_gnu_backtracer_generate;
}

static void
gum_gnu_backtracer_init (GumGnuBacktracer * self)
{
}

GumBacktracer *
gum_gnu_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_GNU_BACKTRACER, NULL);
}

static void
gum_gnu_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses)
{
  guint skip_count = 0;
  gpointer addresses[8 + GUM_MAX_BACKTRACE_DEPTH - 1];
  guint addr_count;
  guint i;

  if (cpu_context == NULL)
  {
    skip_count = 1;
  }
  else
  {
    /*
     * HACK: we should do the backtrace from the supplied cpu_context,
     *       if only backtrace() was flexible enough... So here we assume
     *       that we're called from the Interceptor's on_enter/on_leave...
     */
    skip_count = 8;
  }

  addr_count = backtrace (addresses, G_N_ELEMENTS (addresses));

  return_addresses->len = 0;

  /* HACK: see above. Here we assume that we're called from on_leave... */
  if (cpu_context != NULL)
  {
    return_addresses->items[return_addresses->len++] =
        GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
  }

  for (i = skip_count; i < addr_count; i++)
  {
    g_assert_cmpuint (return_addresses->len, <,
        G_N_ELEMENTS (return_addresses->items));
    return_addresses->items[return_addresses->len++] =
        addresses[i];
  }
}

