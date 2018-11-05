/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_EVENT_SINK_H__
#define __GUM_EVENT_SINK_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/gumevent.h>

G_BEGIN_DECLS

#define GUM_TYPE_EVENT_SINK (gum_event_sink_get_type ())
G_DECLARE_INTERFACE (GumEventSink, gum_event_sink, GUM, EVENT_SINK, GObject)

struct _GumEventSinkInterface
{
  GTypeInterface parent;

  GumEventType (* query_mask) (GumEventSink * self);
  void (* start) (GumEventSink * self);
  void (* process) (GumEventSink * self, const GumEvent * ev);
  void (* flush) (GumEventSink * self);
  void (* stop) (GumEventSink * self);
};

GUM_API GumEventType gum_event_sink_query_mask (GumEventSink * self);
GUM_API void gum_event_sink_start (GumEventSink * self);
GUM_API void gum_event_sink_process (GumEventSink * self, const GumEvent * ev);
GUM_API void gum_event_sink_flush (GumEventSink * self);
GUM_API void gum_event_sink_stop (GumEventSink * self);

G_END_DECLS

#endif
