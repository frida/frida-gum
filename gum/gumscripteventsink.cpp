/*
 * Copyright (C) 2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscripteventsink.h"

#include "gumscriptpointer.h"
#include "gumscriptscope.h"

#include <string.h>

using namespace v8;

static void gum_script_event_sink_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_script_event_sink_finalize (GObject * obj);
static GumEventType gum_script_event_sink_query_mask (GumEventSink * sink);
static void gum_script_event_sink_start (GumEventSink * sink);
static void gum_script_event_sink_process (GumEventSink * sink,
    const GumEvent * ev);
static void gum_script_event_sink_stop (GumEventSink * sink);
static gboolean gum_script_event_sink_stop_idle (gpointer user_data);
static gboolean gum_script_event_sink_drain (gpointer user_data);
static void gum_script_event_sink_data_free (Persistent<Value> object,
    void * buffer);

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
gum_script_event_sink_finalize (GObject * obj)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  g_object_unref (self->script);

  gum_spinlock_free (&self->lock);
  g_array_free (self->queue, TRUE);

  Locker l;
  HandleScope handle_scope;
  self->on_receive.Dispose ();
  self->on_call_summary.Dispose ();

  G_OBJECT_CLASS (gum_script_event_sink_parent_class)->finalize (obj);
}

GumEventSink *
gum_script_event_sink_new (const GumScriptEventSinkOptions * options)
{
  GumScriptEventSink * sink;

  sink = GUM_SCRIPT_EVENT_SINK (
      g_object_new (GUM_TYPE_SCRIPT_EVENT_SINK, NULL));
  sink->queue = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent),
      options->queue_capacity);
  sink->queue_capacity = options->queue_capacity;
  sink->queue_drain_interval = options->queue_drain_interval;

  g_object_ref (options->script);
  sink->script = options->script;
  sink->main_context = options->main_context;
  sink->event_mask = options->event_mask;
  sink->on_receive = Persistent<Function>::New (options->on_receive);
  sink->on_call_summary = Persistent<Function>::New (options->on_call_summary);

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
  GSource * source;

  source = g_idle_source_new ();
  g_source_set_callback (source, gum_script_event_sink_stop_idle, sink, NULL);
  g_source_attach (source, GUM_SCRIPT_EVENT_SINK (sink)->main_context);
  g_source_unref (source);
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
  g_object_unref (self);

  return FALSE;
}

static gboolean
gum_script_event_sink_drain (gpointer user_data)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (user_data);
  gpointer buffer = NULL;
  guint len, size;

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
    ScriptScope scope (self->script);

    V8::AdjustAmountOfExternalAllocatedMemory (size);

    if (!self->on_call_summary.IsEmpty ())
    {
      GHashTable * frequencies = g_hash_table_new (NULL, NULL);
      GumCallEvent * ev = ev = static_cast<GumCallEvent *> (buffer);
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

      Handle<Object> summary = Object::New ();
      GHashTableIter iter;
      g_hash_table_iter_init (&iter, frequencies);
      gpointer target, count;
      while (g_hash_table_iter_next (&iter, &target, &count))
      {
        summary->Set (_gum_script_pointer_new (self->script, target),
            Number::New (GPOINTER_TO_SIZE (count)), ReadOnly);
      }

      g_hash_table_unref (frequencies);

      Handle<Value> argv[] = { summary };
      self->on_call_summary->Call (self->on_call_summary, 1, argv);
    }

    if (!self->on_receive.IsEmpty ())
    {
      Handle<Object> data = Object::New ();
      data->Set (String::New ("length"), Int32::New (size), ReadOnly);
      data->SetIndexedPropertiesToExternalArrayData (buffer,
          kExternalUnsignedByteArray, size);
      Persistent<Object> persistent_data = Persistent<Object>::New (data);
      persistent_data.MakeWeak (buffer, gum_script_event_sink_data_free);
      persistent_data.MarkIndependent ();

      Handle<Value> argv[] = { data };
      self->on_receive->Call (self->on_receive, 1, argv);
    }
    else
    {
      g_free (buffer);
    }
  }

  return TRUE;
}

static void
gum_script_event_sink_data_free (Persistent<Value> object,
                                 void * buffer)
{
  int32_t size;

  HandleScope handle_scope;
  size = object->ToObject ()->Get (String::New ("length"))->Uint32Value ();
  V8::AdjustAmountOfExternalAllocatedMemory (-size);
  g_free (buffer);
  object.Dispose ();
}
