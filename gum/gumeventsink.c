/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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

    g_once_init_leave (&gonce_value, gtype);
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
