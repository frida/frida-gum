/*
 * Copyright (C) 2017-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_EVENT_SINK_H__
#define __GUM_DUK_EVENT_SINK_H__

#include "gumdukcore.h"

#include <gum/gumeventsink.h>

G_BEGIN_DECLS

#define GUM_DUK_TYPE_JS_EVENT_SINK (gum_duk_js_event_sink_get_type ())
#define GUM_DUK_JS_EVENT_SINK_CAST(obj) ((GumDukJSEventSink *) (obj))
G_DECLARE_FINAL_TYPE (GumDukJSEventSink, gum_duk_js_event_sink, GUM_DUK,
    JS_EVENT_SINK, GObject)

#define GUM_DUK_TYPE_NATIVE_EVENT_SINK (gum_duk_native_event_sink_get_type ())
#define GUM_DUK_NATIVE_EVENT_SINK_CAST(obj) ((GumDukNativeEventSink *) (obj))
G_DECLARE_FINAL_TYPE (GumDukNativeEventSink, gum_duk_native_event_sink, GUM_DUK,
    NATIVE_EVENT_SINK, GObject)

typedef struct _GumDukEventSinkOptions GumDukEventSinkOptions;

typedef void (* GumDukOnEvent) (const GumEvent * event,
    GumCpuContext * cpu_context, gpointer user_data);

struct _GumDukEventSinkOptions
{
  GumDukCore * core;
  GMainContext * main_context;

  GumEventType event_mask;

  guint queue_capacity;
  guint queue_drain_interval;
  GumDukHeapPtr on_receive;
  GumDukHeapPtr on_call_summary;

  GumDukOnEvent on_event;
  gpointer user_data;
};

G_GNUC_INTERNAL GumEventSink * gum_duk_event_sink_new (duk_context * ctx,
    const GumDukEventSinkOptions * options);

G_END_DECLS

#endif
