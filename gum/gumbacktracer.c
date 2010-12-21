/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumbacktracer.h"

#ifdef G_OS_WIN32
#include "backend-dbghelp/gumdbghelpbacktracer.h"
#else
#include "backend-glibc/gumgnubacktracer.h"
#endif

GType
gum_backtracer_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumBacktracer",
        sizeof (GumBacktracerIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, (GType) gtype);
  }

  return (GType) gonce_value;
}

GumBacktracer *
gum_backtracer_make_default (void)
{
#if defined (G_OS_WIN32)
  return gum_dbghelp_backtracer_new ();
#elif defined (HAVE_LINUX)
  return gum_gnu_backtracer_new ();
#else
  return NULL;
#endif
}

void
gum_backtracer_generate (GumBacktracer * self,
                         const GumCpuContext * cpu_context,
                         GumReturnAddressArray * return_addresses)
{
  GumBacktracerIface * iface = GUM_BACKTRACER_GET_INTERFACE (self);

  g_assert (iface->generate != NULL);

  iface->generate (self, cpu_context, return_addresses);
}
