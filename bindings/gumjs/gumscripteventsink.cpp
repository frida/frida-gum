/*
 * Copyright (C) 2012-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscripteventsink.h"

#include "gumscriptcore.h"
#include "gumscriptscope.h"

#include <string.h>

using namespace v8;

static void gum_script_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_script_event_sink_dispose (GObject * obj);
static void gum_script_event_sink_finalize (GObject * obj);
static GumEventType gum_script_event_sink_query_mask (GumEventSink * sink);
static void gum_script_event_sink_start (GumEventSink * sink);
static void gum_script_event_sink_process (GumEventSink * sink,
    const GumEvent * ev);
static void gum_script_event_sink_stop (GumEventSink * sink);
static gboolean gum_script_event_sink_stop_idle (gpointer user_data);
static gboolean gum_script_event_sink_drain (gpointer user_data);

G_DEFINE_TYPE_EXTENDED (GumScriptEventSink,
                        gum_script_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_script_event_sink_iface_init));

static void
gum_script_event_sink_class_init (GumScriptEventSinkClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_script_event_sink_dispose;
  object_class->finalize = gum_script_event_sink_finalize;
}

static void
gum_script_event_sink_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumEventSinkIface * iface = (GumEventSinkIface *) g_iface;

  (void) iface_data;

  iface->query_mask = gum_script_event_sink_query_mask;
  iface->start = gum_script_event_sink_start;
  iface->process = gum_script_event_sink_process;
  iface->stop = gum_script_event_sink_stop;
}

static void
gum_script_event_sink_init (GumScriptEventSink * self)
{
  gum_spinlock_init (&self->lock);
}

static void
gum_script_event_sink_release_core (GumScriptEventSink * self)
{
  GumScript * script;

  if (self->core == NULL)
    return;
  script = self->core->script;
  self->core = NULL;

  {
    ScriptScope scope (script);
    delete self->on_receive;
    self->on_receive = NULL;
    delete self->on_call_summary;
    self->on_call_summary = NULL;
  }

  g_object_unref (script);
}

static void
gum_script_event_sink_dispose (GObject * obj)
{
  gum_script_event_sink_release_core (GUM_SCRIPT_EVENT_SINK (obj));

  G_OBJECT_CLASS (gum_script_event_sink_parent_class)->dispose (obj);
}

static void
gum_script_event_sink_finalize (GObject * obj)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  gum_spinlock_free (&self->lock);
  g_array_free (self->queue, TRUE);

  G_OBJECT_CLASS (gum_script_event_sink_parent_class)->finalize (obj);
}

GumEventSink *
gum_script_event_sink_new (const GumScriptEventSinkOptions * options)
{
  Isolate * isolate = options->core->isolate;
  GumScriptEventSink * sink;

  sink = GUM_SCRIPT_EVENT_SINK (
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
gum_script_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_SCRIPT_EVENT_SINK (sink)->event_mask;
}

static void
gum_script_event_sink_start (GumEventSink * sink)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (sink);
  self->source = g_timeout_source_new (self->queue_drain_interval);
  g_source_set_callback (self->source, gum_script_event_sink_drain,
      g_object_ref (self), g_object_unref);
  g_source_attach (self->source, self->main_context);
}

static void
gum_script_event_sink_process (GumEventSink * sink,
                               const GumEvent * ev)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK_CAST (sink);
  gum_spinlock_acquire (&self->lock);
  if (self->queue->len != self->queue_capacity)
    g_array_append_val (self->queue, *ev);
  gum_spinlock_release (&self->lock);
}

static void
gum_script_event_sink_stop (GumEventSink * sink)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (sink);

  if (g_main_context_is_owner (self->main_context))
  {
    gum_script_event_sink_stop_idle (sink);
  }
  else
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_callback (source, gum_script_event_sink_stop_idle, sink, NULL);
    g_source_attach (source, self->main_context);
    g_source_unref (source);
  }
}

static gboolean
gum_script_event_sink_stop_idle (gpointer user_data)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (user_data);

  gum_script_event_sink_drain (self);

  g_object_ref (self);
  g_source_destroy (self->source);
  g_source_unref (self->source);
  self->source = NULL;
  gum_script_event_sink_release_core (self);
  g_object_unref (self);

  return FALSE;
}

static gboolean
gum_script_event_sink_drain (gpointer user_data)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (user_data);
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

    if (self->on_call_summary != NULL)
    {
      frequencies = g_hash_table_new (NULL, NULL);

      GumCallEvent * ev = static_cast<GumCallEvent *> (buffer);
      for (guint i = 0; i != len; i++)
      {
        if (ev->type == GUM_CALL)
        {
          gsize count = GPOINTER_TO_SIZE (
              g_hash_table_lookup (frequencies, ev->target));
          count++;
          g_hash_table_insert (frequencies,
              ev->target, GSIZE_TO_POINTER (count));
        }

        ev++;
      }
    }

    ScriptScope scope (self->core->script);
    Isolate * isolate = self->core->isolate;

    if (frequencies != NULL)
    {
      Handle<Object> summary = Object::New (isolate);

      GHashTableIter iter;
      g_hash_table_iter_init (&iter, frequencies);
      gpointer target, count;
      Local<Context> jc = isolate->GetCurrentContext ();
      while (g_hash_table_iter_next (&iter, &target, &count))
      {
        Maybe<bool> success = summary->ForceSet (jc,
            _gum_script_pointer_new (target, self->core),
            Number::New (isolate, GPOINTER_TO_SIZE (count)),
            static_cast<PropertyAttribute> (ReadOnly | DontDelete));
        g_assert (success.IsJust ());
      }

      g_hash_table_unref (frequencies);

      Handle<Value> argv[] = { summary };
      Local<Function> on_call_summary (Local<Function>::New (isolate,
          *self->on_call_summary));
      on_call_summary->Call (on_call_summary, 1, argv);
    }

    if (self->on_receive != NULL)
    {
      Local<Function> on_receive (Local<Function>::New (isolate,
          *self->on_receive));
      Local<Value> argv[] = {
          ArrayBuffer::New (isolate, buffer, size,
              ArrayBufferCreationMode::kInternalized)
      };
      on_receive->Call (on_receive, 1, argv);
    }
    else
    {
      g_free (buffer);
    }
  }

  return TRUE;
}
