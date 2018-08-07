/*
 * Copyright (C) 2012-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_EVENT_SINK_H__
#define __GUM_V8_EVENT_SINK_H__

#include "gumv8core.h"

#include <gum/gumeventsink.h>

#define GUM_V8_TYPE_EVENT_SINK (gum_v8_event_sink_get_type ())
#define GUM_V8_EVENT_SINK_CAST(obj) ((GumV8EventSink *) (obj))
G_DECLARE_FINAL_TYPE (GumV8EventSink, gum_v8_event_sink, GUM_V8, EVENT_SINK,
    GObject)

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

G_GNUC_INTERNAL GumEventSink * gum_v8_event_sink_new (
    const GumV8EventSinkOptions * options);

#endif
