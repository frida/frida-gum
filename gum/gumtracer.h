/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_TRACER_H__
#define __GUM_TRACER_H__

#include "gumdefs.h"
#include "gumfunction.h"

#include <glib-object.h>

#define GUM_TYPE_TRACER (gum_tracer_get_type ())
#define GUM_TRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_TRACER, GumTracer))
#define GUM_TRACER_CAST(obj) ((GumTracer *) (obj))
#define GUM_TRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_TRACER, GumTracerClass))
#define GUM_IS_TRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_TRACER))
#define GUM_IS_TRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_TRACER))
#define GUM_TRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_TRACER, GumTracerClass))

#define GUM_TRACE_ENTRY_TYPE(e)         ((e)->entry.header.type)
#define GUM_TRACE_ENTRY_NAME_ID(e)      ((e)->entry.header.name_id)
#define GUM_TRACE_ENTRY_THREAD_ID(e)    ((e)->entry.header.thread_id)
#define GUM_TRACE_ENTRY_DEPTH(e)        ((e)->entry.header.depth)
#define GUM_TRACE_ENTRY_TIMESTAMP(e)    ((e)->entry.header.timestamp)
#define GUM_TRACE_ENTRY_ARGLIST_SIZE(e) ((e)->entry.header.arglist_size)

#define GUM_TRACE_ENTRY_DATA(e)         ((e)->entry.data.buf)

G_BEGIN_DECLS

typedef struct _GumTracer           GumTracer;
typedef struct _GumTracerClass      GumTracerClass;
typedef struct _GumTracerPrivate    GumTracerPrivate;

typedef struct _GumTraceEntry       GumTraceEntry;
typedef enum _GumEntryType          GumEntryType;

struct _GumTracer
{
  GObject parent;

  GumTracerPrivate * priv;
};

struct _GumTracerClass
{
  GObjectClass parent_class;
};

enum _GumEntryType
{
  GUM_ENTRY_INVALID,
  GUM_ENTRY_ENTER,
  GUM_ENTRY_LEAVE
};

struct _GumTraceEntry
{
  union
  {
    struct _GumTraceEntryHeader
    {
      GumEntryType type;
      guint name_id;
      guint thread_id;
      guint depth;
      guint timestamp;
      guint arglist_size;
    } header;

    struct _GumTraceEntryData
    {
      gchar buf[32];
    } data;
  } entry;
};

GUM_API GType gum_tracer_get_type (void) G_GNUC_CONST;

GUM_API GumTracer * gum_tracer_new (void);

GUM_API gboolean gum_tracer_add_function (GumTracer * self,
    const gchar * name, gpointer address);
GUM_API gboolean gum_tracer_add_function_with (GumTracer * self,
    GumFunctionDetails * details);
GUM_API const gchar * gum_tracer_name_id_to_string (GumTracer * self,
    guint id);
GUM_API GumTraceEntry * gum_tracer_drain (GumTracer * self,
    guint * num_entries);

G_END_DECLS

#endif
