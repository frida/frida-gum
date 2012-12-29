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

#ifndef __GUM_SCRIPT_EVENT_SINK_H__
#define __GUM_SCRIPT_EVENT_SINK_H__

#include "gumeventsink.h"
#include "gumscript.h"
#include "gumspinlock.h"

#include <glib-object.h>
#include <v8.h>

#define GUM_TYPE_SCRIPT_EVENT_SINK (gum_script_event_sink_get_type ())
#define GUM_SCRIPT_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT_EVENT_SINK, GumScriptEventSink))
#define GUM_SCRIPT_EVENT_SINK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_SCRIPT_EVENT_SINK, GumScriptEventSinkClass))
#define GUM_IS_SCRIPT_EVENT_SINK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT_EVENT_SINK))
#define GUM_IS_SCRIPT_EVENT_SINK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_SCRIPT_EVENT_SINK))
#define GUM_SCRIPT_EVENT_SINK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_SCRIPT_EVENT_SINK, GumScriptEventSinkClass))

typedef struct _GumScriptEventSink GumScriptEventSink;
typedef struct _GumScriptEventSinkClass GumScriptEventSinkClass;

struct _GumScriptEventSink
{
  GObject parent;
  GumSpinlock lock;
  GArray * events;

  GumScript * script;
  v8::Persistent<v8::Function> on_receive;
  GSource * source;
};

struct _GumScriptEventSinkClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_script_event_sink_get_type (void) G_GNUC_CONST;

GumEventSink * gum_script_event_sink_new (GumScript * script,
    GMainContext * main_context, v8::Handle<v8::Function> on_receive);

G_END_DECLS

#endif
