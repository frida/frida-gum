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

#include "guminvocationlistener.h"

GType
gum_invocation_listener_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE,
        "GumInvocationListener", sizeof (GumInvocationListenerIface),
        NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, (GType) gtype);
  }

  return (GType) gonce_value;
}

void
gum_invocation_listener_on_enter (GumInvocationListener * self,
                                  GumInvocationContext * ctx)
{
  GUM_INVOCATION_LISTENER_GET_INTERFACE (self)->on_enter (self, ctx);
}

void
gum_invocation_listener_on_leave (GumInvocationListener * self,
                                  GumInvocationContext * ctx)
{
  GUM_INVOCATION_LISTENER_GET_INTERFACE (self)->on_leave (self, ctx);
}

gpointer
gum_invocation_listener_provide_thread_data (GumInvocationListener * self,
                                             gpointer function_instance_data,
                                             guint thread_id)
{
  return GUM_INVOCATION_LISTENER_GET_INTERFACE (self)->provide_thread_data (
      self, function_instance_data, thread_id);
}
