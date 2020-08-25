/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumeventsink.h"

struct _GumDefaultEventSink
{
  GObject parent;
};

static void gum_default_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumEventType gum_default_event_sink_query_mask (GumEventSink * sink);
static void gum_default_event_sink_process (GumEventSink * sink,
    const GumEvent * ev);

G_DEFINE_INTERFACE (GumEventSink, gum_event_sink, G_TYPE_OBJECT)

G_DEFINE_TYPE_EXTENDED (GumDefaultEventSink,
                        gum_default_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_default_event_sink_iface_init))

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

GumEventSink *
gum_event_sink_make_default (void)
{
  return GUM_EVENT_SINK (g_object_new (GUM_TYPE_DEFAULT_EVENT_SINK, NULL));
}

static void
gum_default_event_sink_class_init (GumDefaultEventSinkClass * klass)
{
}

static void
gum_default_event_sink_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumEventSinkInterface * iface = g_iface;

  iface->query_mask = gum_default_event_sink_query_mask;
  iface->process = gum_default_event_sink_process;
}

static void
gum_default_event_sink_init (GumDefaultEventSink * self)
{
}

static GumEventType
gum_default_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_NOTHING;
}

static void
gum_default_event_sink_process (GumEventSink * sink,
                                const GumEvent * ev)
{
}

