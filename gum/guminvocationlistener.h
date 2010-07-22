/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_INVOCATION_LISTENER_H__
#define __GUM_INVOCATION_LISTENER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_INVOCATION_LISTENER (gum_invocation_listener_get_type ())
#define GUM_INVOCATION_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_INVOCATION_LISTENER, GumInvocationListener))
#define GUM_IS_INVOCATION_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_INVOCATION_LISTENER))
#define GUM_INVOCATION_LISTENER_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_INVOCATION_LISTENER, GumInvocationListenerIface))

typedef struct _GumInvocationListener GumInvocationListener;
typedef struct _GumInvocationListenerIface GumInvocationListenerIface;
typedef struct _GumInvocationBackend GumInvocationBackend;
typedef struct _GumInvocationContext GumInvocationContext;

struct _GumInvocationListenerIface
{
  GTypeInterface parent;

  void (*on_enter) (GumInvocationListener * self, GumInvocationContext * ctx);
  void (*on_leave) (GumInvocationListener * self, GumInvocationContext * ctx);
  gpointer (*provide_thread_data) (GumInvocationListener * self,
      gpointer function_instance_data, guint thread_id);
};

struct _GumInvocationBackend
{
  gpointer (* get_nth_argument) (GumInvocationContext * context, guint n);
  gpointer (* get_return_value) (GumInvocationContext * context);

  gpointer user_data;
};

struct _GumInvocationContext
{
  GumInvocationContext * parent;

  gpointer instance_data;
  gpointer thread_data;

  GumCpuContext * cpu_context;

  /*< private */
  GumInvocationBackend * backend;
};

G_BEGIN_DECLS

GUM_API GType gum_invocation_listener_get_type (void);

GUM_API void gum_invocation_listener_on_enter (GumInvocationListener * self,
    GumInvocationContext * ctx);
GUM_API void gum_invocation_listener_on_leave (GumInvocationListener * self,
    GumInvocationContext * ctx);
GUM_API gpointer gum_invocation_listener_provide_thread_data (
    GumInvocationListener * self, gpointer function_instance_data,
    guint thread_id);

GUM_API gpointer gum_invocation_context_get_nth_argument (
    GumInvocationContext * context, guint n);
GUM_API gpointer gum_invocation_context_get_return_value (
    GumInvocationContext * context);
/* TODO: remove this when migration is complete */
GUM_API gpointer gum_invocation_context_get_stack_pointer (
    GumInvocationContext * context);

G_END_DECLS

#endif
