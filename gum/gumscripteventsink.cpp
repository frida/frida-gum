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

#include "gumscriptscope.h"

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

  iface->query_mask = gum_script_event_sink_query_mask;
  iface->start = gum_script_event_sink_start;
  iface->process = gum_script_event_sink_process;
  iface->stop = gum_script_event_sink_stop;
}

static void
gum_script_event_sink_init (GumScriptEventSink * self)
{
  gum_spinlock_init (&self->lock);
  self->events = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent), 16384);
}

static void
gum_script_event_sink_finalize (GObject * obj)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (obj);

  g_assert (self->source == NULL);

  gum_spinlock_free (&self->lock);
  g_array_free (self->events, TRUE);

  self->on_receive.Dispose ();

  G_OBJECT_CLASS (gum_script_event_sink_parent_class)->finalize (obj);
}

GumEventSink *
gum_script_event_sink_new (GumScript * script,
                           GMainContext * main_context,
                           Handle<Function> on_receive)
{
  GumScriptEventSink * sink;

  sink = GUM_SCRIPT_EVENT_SINK (
      g_object_new (GUM_TYPE_SCRIPT_EVENT_SINK, NULL));
  sink->script = script;
  sink->main_context = main_context;
  sink->on_receive = Persistent<Function>::New (on_receive);

  return GUM_EVENT_SINK (sink);
}

static GumEventType
gum_script_event_sink_query_mask (GumEventSink * sink)
{
  (void) sink;

  return GUM_CALL;
}

static void
gum_script_event_sink_start (GumEventSink * sink)
{
  GumScriptEventSink * self = GUM_SCRIPT_EVENT_SINK (sink);
  self->source = g_timeout_source_new (250);
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
  if (self->events->len != 16384)
    g_array_append_val (self->events, *ev);
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
  GArray * raw_events = NULL;

  gum_spinlock_acquire (&self->lock);
  if (self->events->len > 0)
  {
    raw_events = self->events;
    self->events = g_array_sized_new (FALSE, FALSE, sizeof (GumEvent), 16384);
  }
  gum_spinlock_release (&self->lock);

  if (raw_events != NULL)
  {
    ScriptScope scope (self->script);

    Local<Array> events = Array::New (raw_events->len);
    for (guint i = 0; i != raw_events->len; i++)
    {
      GumCallEvent * raw_event = &g_array_index (raw_events, GumCallEvent, i);
      Local<Object> event (Object::New ());
      event->Set (String::New ("location"),
          Number::New (GPOINTER_TO_SIZE (raw_event->location)),
          ReadOnly);
      event->Set (String::New ("target"),
          Number::New (GPOINTER_TO_SIZE (raw_event->target)),
          ReadOnly);
      event->Set (String::New ("depth"),
          Int32::New (GPOINTER_TO_SIZE (raw_event->depth)),
          ReadOnly);
      events->Set (v8::Number::New (i), event);
    }

    Handle<Value> argv[] = { events };
    self->on_receive->Call (self->on_receive, 1, argv);
  }

  return TRUE;
}
