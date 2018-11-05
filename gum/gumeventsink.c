/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumeventsink.h"

G_DEFINE_INTERFACE (GumEventSink, gum_event_sink, G_TYPE_OBJECT)

static void
gum_event_sink_default_init (GumEventSinkInterface * iface)
{
}

GumEventType
gum_event_sink_query_mask (GumEventSink * self)
{
  GumEventSinkInterface * iface = GUM_EVENT_SINK_GET_IFACE (self);

  g_assert (iface->query_mask != NULL);

  return iface->query_mask (self);
}

void
gum_event_sink_start (GumEventSink * self)
{
  GumEventSinkInterface * iface = GUM_EVENT_SINK_GET_IFACE (self);

  if (iface->start != NULL)
    iface->start (self);
}

void
gum_event_sink_process (GumEventSink * self,
                        const GumEvent * ev)
{
  GumEventSinkInterface * iface = GUM_EVENT_SINK_GET_IFACE (self);

  g_assert (iface->process != NULL);

  iface->process (self, ev);
}

void
gum_event_sink_flush (GumEventSink * self)
{
  GumEventSinkInterface * iface = GUM_EVENT_SINK_GET_IFACE (self);

  if (iface->flush != NULL)
    iface->flush (self);
}

void
gum_event_sink_stop (GumEventSink * self)
{
  GumEventSinkInterface * iface = GUM_EVENT_SINK_GET_IFACE (self);

  if (iface->stop != NULL)
    iface->stop (self);
}
