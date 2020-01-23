/*
 * Copyright (C) 2017-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukeventsink.h"

#include "gumdukvalue.h"

#include <gum/gumspinlock.h>
#include <string.h>

static void gum_duk_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_event_sink_dispose (GObject * obj);
static void gum_duk_event_sink_finalize (GObject * obj);
static GumEventType gum_duk_event_sink_query_mask (GumEventSink * sink);
static void gum_duk_event_sink_start (GumEventSink * sink);
static void gum_duk_event_sink_process (GumEventSink * sink,
    const GumEvent * ev);
static void gum_duk_event_sink_flush (GumEventSink * sink);
static void gum_duk_event_sink_stop (GumEventSink * sink);
static gboolean gum_duk_event_sink_stop_when_idle (GumDukEventSink * self);
static gboolean gum_duk_event_sink_drain (GumDukEventSink * self);

struct _GumDukEventSink
{
  GObject parent;

  GumSpinlock lock;
  GArray * queue;
  guint queue_capacity;
  guint queue_drain_interval;

  GumDukCore * core;
  GMainContext * main_context;
  GumEventType event_mask;
  GumDukHeapPtr on_receive;
  GumDukHeapPtr on_call_summary;
  GSource * source;
};

G_DEFINE_TYPE_EXTENDED (GumDukEventSink,
                        gum_duk_event_sink,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_EVENT_SINK,
                            gum_duk_event_sink_iface_init))

static void
gum_duk_event_sink_class_init (GumDukEventSinkClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_event_sink_dispose;
  object_class->finalize = gum_duk_event_sink_finalize;
}

static void
gum_duk_event_sink_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumEventSinkInterface * iface = g_iface;

  iface->query_mask = gum_duk_event_sink_query_mask;
  iface->start = gum_duk_event_sink_start;
  iface->process = gum_duk_event_sink_process;
  iface->flush = gum_duk_event_sink_flush;
  iface->stop = gum_duk_event_sink_stop;
}

static void
gum_duk_event_sink_init (GumDukEventSink * self)
{
  gum_spinlock_init (&self->lock);
}

static void
gum_duk_event_sink_release_core (GumDukEventSink * self)
{
  GumDukCore * core;

  core = g_steal_pointer (&self->core);
  if (core == NULL)
    return;

  {
    GumDukScope scope;
    duk_context * ctx;

    ctx = _gum_duk_scope_enter (&scope, core);

    _gum_duk_unprotect (ctx, g_steal_pointer (&self->on_receive));
    _gum_duk_unprotect (ctx, g_steal_pointer (&self->on_call_summary));

    _gum_duk_scope_leave (&scope);
  }

  g_object_unref (core->script);
}

static void
gum_duk_event_sink_dispose (GObject * obj)
{
  gum_duk_event_sink_release_core (GUM_DUK_EVENT_SINK (obj));

  G_OBJECT_CLASS (gum_duk_event_sink_parent_class)->dispose (obj);
}

static void
gum_duk_event_sink_finalize (GObject * obj)
{
  GumDukEventSink * self = GUM_DUK_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  g_array_free (self->queue, TRUE);

  G_OBJECT_CLASS (gum_duk_event_sink_parent_class)->finalize (obj);
}

GumEventSink *
gum_duk_event_sink_new (duk_context * ctx,
                        const GumDukEventSinkOptions * options)
{
  GumDukEventSink * sink;

  sink = g_object_new (GUM_DUK_TYPE_EVENT_SINK, NULL);
  sink->queue = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent),
      options->queue_capacity);
  sink->queue_capacity = options->queue_capacity;
  sink->queue_drain_interval = options->queue_drain_interval;

  g_object_ref (options->core->script);
  sink->core = options->core;
  sink->main_context = options->main_context;
  sink->event_mask = options->event_mask;

  sink->on_receive = options->on_receive;
  _gum_duk_protect (ctx, sink->on_receive);
  sink->on_call_summary = options->on_call_summary;
  _gum_duk_protect (ctx, sink->on_call_summary);

  return GUM_EVENT_SINK (sink);
}

static GumEventType
gum_duk_event_sink_query_mask (GumEventSink * sink)
{
  return GUM_DUK_EVENT_SINK (sink)->event_mask;
}

static void
gum_duk_event_sink_start (GumEventSink * sink)
{
  GumDukEventSink * self = GUM_DUK_EVENT_SINK (sink);

  if (self->queue_drain_interval != 0)
  {
    self->source = g_timeout_source_new (self->queue_drain_interval);
    g_source_set_callback (self->source, (GSourceFunc) gum_duk_event_sink_drain,
        g_object_ref (self), g_object_unref);
    g_source_attach (self->source, self->main_context);
  }
}

static void
gum_duk_event_sink_process (GumEventSink * sink,
                           const GumEvent * ev)
{
  GumDukEventSink * self = GUM_DUK_EVENT_SINK_CAST (sink);

  gum_spinlock_acquire (&self->lock);
  if (self->queue->len != self->queue_capacity)
    g_array_append_val (self->queue, *ev);
  gum_spinlock_release (&self->lock);
}

static void
gum_duk_event_sink_flush (GumEventSink * sink)
{
  gum_duk_event_sink_drain (GUM_DUK_EVENT_SINK (sink));
}

static void
gum_duk_event_sink_stop (GumEventSink * sink)
{
  GumDukEventSink * self = GUM_DUK_EVENT_SINK (sink);

  if (g_main_context_is_owner (self->main_context))
  {
    gum_duk_event_sink_stop_when_idle (self);
  }
  else
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_callback (source,
        (GSourceFunc) gum_duk_event_sink_stop_when_idle, g_object_ref (self),
        g_object_unref);
    g_source_attach (source, self->main_context);
    g_source_unref (source);
  }
}

static gboolean
gum_duk_event_sink_stop_when_idle (GumDukEventSink * self)
{
  gum_duk_event_sink_drain (self);

  g_object_ref (self);

  if (self->source != NULL)
  {
    g_source_destroy (self->source);
    g_source_unref (self->source);
    self->source = NULL;
  }

  gum_duk_event_sink_release_core (self);

  g_object_unref (self);

  return FALSE;
}

static gboolean
gum_duk_event_sink_drain (GumDukEventSink * self)
{
  GumDukCore * core = self->core;
  gpointer buffer_data;
  guint len, size;
  GumDukScope scope;
  duk_context * ctx;

  if (core == NULL)
    return FALSE;

  len = self->queue->len;
  if (len == 0)
    return TRUE;
  size = len * sizeof (GumEvent);

  ctx = _gum_duk_scope_enter (&scope, core);

  buffer_data = duk_push_fixed_buffer (ctx, size);
  memcpy (buffer_data, self->queue->data, size);

  gum_spinlock_acquire (&self->lock);
  g_array_remove_range (self->queue, 0, len);
  gum_spinlock_release (&self->lock);

  if (self->on_call_summary != NULL)
  {
    GHashTable * frequencies;
    GumCallEvent * ev;
    guint i;
    GHashTableIter iter;
    gpointer target, count;
    gchar target_str[32];

    frequencies = g_hash_table_new (NULL, NULL);

    ev = buffer_data;
    for (i = 0; i != len; i++)
    {
      if (ev->type == GUM_CALL)
      {
        gsize n;

        n = GPOINTER_TO_SIZE (g_hash_table_lookup (frequencies, ev->target));
        n++;
        g_hash_table_insert (frequencies, ev->target, GSIZE_TO_POINTER (n));
      }

      ev++;
    }

    duk_push_heapptr (ctx, self->on_call_summary);

    duk_push_object (ctx);

    g_hash_table_iter_init (&iter, frequencies);
    while (g_hash_table_iter_next (&iter, &target, &count))
    {
      sprintf (target_str, "0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (target));
      duk_push_uint (ctx, GPOINTER_TO_SIZE (count));
      duk_put_prop_string (ctx, -2, target_str);
    }

    g_hash_table_unref (frequencies);

    _gum_duk_scope_call (&scope, 1);
    duk_pop (ctx);
  }

  if (self->on_receive != NULL)
  {
    duk_push_heapptr (ctx, self->on_receive);

    duk_push_buffer_object (ctx, -2, 0, size, DUK_BUFOBJ_ARRAYBUFFER);

    _gum_duk_scope_call (&scope, 1);
    duk_pop_2 (ctx);
  }
  else
  {
    duk_pop (ctx);
  }

  _gum_duk_scope_leave (&scope);

  return TRUE;
}
