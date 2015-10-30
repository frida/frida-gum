/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_EVENT_SINK_H__
#define __GUM_EVENT_SINK_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/gumevent.h>

#define GUM_TYPE_EVENT_SINK (gum_event_sink_get_type ())
#define GUM_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_EVENT_SINK, GumEventSink))
#define GUM_IS_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_EVENT_SINK))
#define GUM_EVENT_SINK_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_EVENT_SINK, GumEventSinkIface))

typedef struct _GumEventSink GumEventSink;
typedef struct _GumEventSinkIface GumEventSinkIface;

struct _GumEventSinkIface
{
  GTypeInterface parent;

  GumEventType (* query_mask) (GumEventSink * self);
  void (* start) (GumEventSink * self);
  void (* process) (GumEventSink * self, const GumEvent * ev);
  void (* stop) (GumEventSink * self);
};

G_BEGIN_DECLS

GType gum_event_sink_get_type (void);

GUM_API GumEventType gum_event_sink_query_mask (GumEventSink * self);
GUM_API void gum_event_sink_start (GumEventSink * self);
GUM_API void gum_event_sink_process (GumEventSink * self, const GumEvent * ev);
GUM_API void gum_event_sink_stop (GumEventSink * self);

G_END_DECLS

#endif
