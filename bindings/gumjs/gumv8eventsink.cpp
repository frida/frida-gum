/*
 * Copyright (C) 2012-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8eventsink.h"

#include "gumv8scope.h"
#include "gumv8value.h"

#include <string.h>

using namespace v8;

static void gum_v8_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_event_sink_dispose (GObject * obj);
static void gum_v8_event_sink_finalize (GObject * obj);
static GumEventType gum_v8_event_sink_query_mask (GumEventSink * sink);
static void gum_v8_event_sink_start (GumEventSink * sink);
static void gum_v8_event_sink_process (GumEventSink * sink,
    const GumEvent * ev);
static void gum_v8_event_sink_stop (GumEventSink * sink);
static gboolean gum_v8_event_sink_stop_when_idle (GumV8EventSink * self);
static gboolean gum_v8_event_sink_drain (GumV8EventSink * self);

G_DEFINE_TYPE_EXTENDED (GumV8EventSink,
                        gum_v8_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_v8_event_sink_iface_init));

static void
gum_v8_event_sink_class_init (GumV8EventSinkClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_event_sink_dispose;
  object_class->finalize = gum_v8_event_sink_finalize;
}

static void
gum_v8_event_sink_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  auto iface = (GumEventSinkIface *) g_iface;

  (void) iface_data;

  iface->query_mask = gum_v8_event_sink_query_mask;
  iface->start = gum_v8_event_sink_start;
  iface->process = gum_v8_event_sink_process;
  iface->stop = gum_v8_event_sink_stop;
}

static void
gum_v8_event_sink_init (GumV8EventSink * self)
{
  gum_spinlock_init (&self->lock);
}

static void
gum_v8_event_sink_release_core (GumV8EventSink * self)
{
  if (self->core == NULL)
    return;

  auto script = self->core->script;
  self->core = NULL;

  {
    ScriptScope scope (script);

    delete self->on_receive;
    self->on_receive = nullptr;

    delete self->on_call_summary;
    self->on_call_summary = nullptr;
  }

  g_object_unref (script);
}

static void
gum_v8_event_sink_dispose (GObject * obj)
{
  gum_v8_event_sink_release_core (GUM_V8_EVENT_SINK (obj));

  G_OBJECT_CLASS (gum_v8_event_sink_parent_class)->dispose (obj);
}

static void
gum_v8_event_sink_finalize (GObject * obj)
{
  auto self = GUM_V8_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  gum_spinlock_free (&self->lock);
  g_array_free (self->queue, TRUE);

  G_OBJECT_CLASS (gum_v8_event_sink_parent_class)->finalize (obj);
}

GumEventSink *
gum_v8_event_sink_new (const GumV8EventSinkOptions * options)
{
  auto isolate = options->core->isolate;

  auto sink = GUM_V8_EVENT_SINK (
      g_object_new (GUM_TYPE_SCRIPT_EVENT_SINK, NULL));
  sink->queue = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent),
      options->queue_capacity);
  sink->queue_capacity = options->queue_capacity;
  sink->queue_drain_interval = options->queue_drain_interval;

  g_object_ref (options->core->script);
  sink->core = options->core;
  sink->main_context = options->main_context;
  sink->event_mask = options->event_mask;
  if (!options->on_receive.IsEmpty ())
  {
    sink->on_receive =
        new GumPersistent<Function>::type (isolate, options->on_receive);
  }
  if (!options->on_call_summary.IsEmpty ())
  {
    sink->on_call_summary =
        new GumPersistent<Function>::type (isolate, options->on_call_summary);
  }

  return GUM_EVENT_SINK (sink);
}

static GumEventType
gum_v8_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_V8_EVENT_SINK (sink)->event_mask;
}

static void
gum_v8_event_sink_start (GumEventSink * sink)
{
  auto self = GUM_V8_EVENT_SINK (sink);

  self->source = g_timeout_source_new (self->queue_drain_interval);
  g_source_set_callback (self->source, (GSourceFunc) gum_v8_event_sink_drain,
      g_object_ref (self), g_object_unref);
  g_source_attach (self->source, self->main_context);
}

static void
gum_v8_event_sink_process (GumEventSink * sink,
                           const GumEvent * ev)
{
  auto self = GUM_V8_EVENT_SINK_CAST (sink);

  gum_spinlock_acquire (&self->lock);
  if (self->queue->len != self->queue_capacity)
    g_array_append_val (self->queue, *ev);
  gum_spinlock_release (&self->lock);
}

static void
gum_v8_event_sink_stop (GumEventSink * sink)
{
  auto self = GUM_V8_EVENT_SINK (sink);

  if (g_main_context_is_owner (self->main_context))
  {
    gum_v8_event_sink_stop_when_idle (self);
  }
  else
  {
    auto source = g_idle_source_new ();
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_event_sink_stop_when_idle, sink, NULL);
    g_source_attach (source, self->main_context);
    g_source_unref (source);
  }
}

static gboolean
gum_v8_event_sink_stop_when_idle (GumV8EventSink * self)
{
  gum_v8_event_sink_drain (self);

  g_object_ref (self);

  g_source_destroy (self->source);
  g_source_unref (self->source);
  self->source = NULL;

  gum_v8_event_sink_release_core (self);

  g_object_unref (self);

  return FALSE;
}

static gboolean
gum_v8_event_sink_drain (GumV8EventSink * self)
{
  gpointer buffer = NULL;
  guint len, size;

  if (self->core == NULL)
    return FALSE;

  len = self->queue->len;
  size = len * sizeof (GumEvent);
  if (len != 0)
  {
    buffer = g_memdup (self->queue->data, size);

    gum_spinlock_acquire (&self->lock);
    g_array_remove_range (self->queue, 0, len);
    gum_spinlock_release (&self->lock);
  }

  if (buffer != NULL)
  {
    GHashTable * frequencies = NULL;

    if (self->on_call_summary != nullptr)
    {
      frequencies = g_hash_table_new (NULL, NULL);

      auto ev = (GumCallEvent *) buffer;
      for (guint i = 0; i != len; i++)
      {
        if (ev->type == GUM_CALL)
        {
          auto count = GPOINTER_TO_SIZE (
              g_hash_table_lookup (frequencies, ev->target));
          count++;
          g_hash_table_insert (frequencies, ev->target,
              GSIZE_TO_POINTER (count));
        }

        ev++;
      }
    }

    ScriptScope scope (self->core->script);
    auto isolate = self->core->isolate;

    if (frequencies != NULL)
    {
      auto summary = Object::New (isolate);

      GHashTableIter iter;
      g_hash_table_iter_init (&iter, frequencies);
      gpointer target, count;
      Local<Context> jc = isolate->GetCurrentContext ();
      while (g_hash_table_iter_next (&iter, &target, &count))
      {
        summary->ForceSet (jc, _gum_v8_native_pointer_new (target, self->core),
            Number::New (isolate, GPOINTER_TO_SIZE (count)),
            (PropertyAttribute) (ReadOnly | DontDelete)).FromJust ();
      }

      g_hash_table_unref (frequencies);

      Local<Value> argv[] = { summary };
      auto on_call_summary =
          Local<Function>::New (isolate, *self->on_call_summary);
      on_call_summary->Call (on_call_summary, G_N_ELEMENTS (argv), argv);
    }

    if (self->on_receive != nullptr)
    {
      auto on_receive = Local<Function>::New (isolate, *self->on_receive);
      Local<Value> argv[] = {
        ArrayBuffer::New (isolate, buffer, size,
            ArrayBufferCreationMode::kInternalized)
      };
      on_receive->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);
    }
    else
    {
      g_free (buffer);
    }
  }

  return TRUE;
}
