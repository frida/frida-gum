/*
 * Copyright (C) 2012-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_EVENT_SINK_H__
#define __GUM_V8_EVENT_SINK_H__

#include "gumv8core.h"

#include <gum/gumeventsink.h>
#include <gum/gumspinlock.h>

#define GUM_TYPE_SCRIPT_EVENT_SINK (gum_v8_event_sink_get_type ())
#define GUM_V8_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT_EVENT_SINK, GumV8EventSink))
#define GUM_V8_EVENT_SINK_CAST(obj) ((GumV8EventSink *) (obj))
#define GUM_V8_EVENT_SINK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_SCRIPT_EVENT_SINK, GumV8EventSinkClass))
#define GUM_IS_SCRIPT_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT_EVENT_SINK))
#define GUM_IS_SCRIPT_EVENT_SINK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_SCRIPT_EVENT_SINK))
#define GUM_V8_EVENT_SINK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_SCRIPT_EVENT_SINK, GumV8EventSinkClass))

struct GumV8EventSink
{
  GObject parent;
  GumSpinlock lock;
  GArray * queue;
  guint queue_capacity;
  guint queue_drain_interval;

  GumV8Core * core;
  GMainContext * main_context;
  GumEventType event_mask;
  GumPersistent<v8::Function>::type * on_receive;
  GumPersistent<v8::Function>::type * on_call_summary;
  GSource * source;
};

struct GumV8EventSinkClass
{
  GObjectClass parent_class;
};

struct GumV8EventSinkOptions
{
  GumV8Core * core;
  GMainContext * main_context;
  GumEventType event_mask;
  guint queue_capacity;
  guint queue_drain_interval;
  v8::Handle<v8::Function> on_receive;
  v8::Handle<v8::Function> on_call_summary;
};

G_GNUC_INTERNAL GType gum_v8_event_sink_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL GumEventSink * gum_v8_event_sink_new (
    const GumV8EventSinkOptions * options);

#endif
