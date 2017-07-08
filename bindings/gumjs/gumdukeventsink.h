/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_EVENT_SINK_H__
#define __GUM_DUK_EVENT_SINK_H__

#include "gumdukcore.h"

#include <gum/gumeventsink.h>

G_BEGIN_DECLS

#define GUM_DUK_TYPE_EVENT_SINK (gum_duk_event_sink_get_type ())
#define GUM_DUK_EVENT_SINK_CAST(obj) ((GumDukEventSink *) (obj))
G_DECLARE_FINAL_TYPE (GumDukEventSink, gum_duk_event_sink, GUM_DUK, EVENT_SINK,
    GObject)

typedef struct _GumDukEventSinkOptions GumDukEventSinkOptions;

struct _GumDukEventSinkOptions
{
  GumDukCore * core;
  GMainContext * main_context;
  GumEventType event_mask;
  guint queue_capacity;
  guint queue_drain_interval;

  GumDukHeapPtr on_receive;
  GumDukHeapPtr on_call_summary;
};

G_GNUC_INTERNAL GumEventSink * gum_duk_event_sink_new (duk_context * ctx,
    const GumDukEventSinkOptions * options);

G_END_DECLS

#endif
