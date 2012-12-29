/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumeventsink.h"

GType
gum_event_sink_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumEventSink",
        sizeof (GumEventSinkIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, (GType) gtype);
  }

  return (GType) gonce_value;
}

GumEventType
gum_event_sink_query_mask (GumEventSink * self)
{
  GumEventSinkIface * iface = GUM_EVENT_SINK_GET_INTERFACE (self);
  g_assert (iface->query_mask != NULL);
  return iface->query_mask (self);
}

void
gum_event_sink_start (GumEventSink * self)
{
  GumEventSinkIface * iface = GUM_EVENT_SINK_GET_INTERFACE (self);
  if (iface->start != NULL)
    iface->start (self);
}

void
gum_event_sink_process (GumEventSink * self,
                        const GumEvent * ev)
{
  GumEventSinkIface * iface = GUM_EVENT_SINK_GET_INTERFACE (self);
  g_assert (iface->process != NULL);
  iface->process (self, ev);
}

void
gum_event_sink_stop (GumEventSink * self)
{
  GumEventSinkIface * iface = GUM_EVENT_SINK_GET_INTERFACE (self);
  if (iface->stop != NULL)
    iface->stop (self);
}
