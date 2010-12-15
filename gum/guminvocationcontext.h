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

#ifndef __GUM_INVOCATION_CONTEXT_H__
#define __GUM_INVOCATION_CONTEXT_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_LINCTX_GET_THREAD_DATA(ctx, data_type) \
    ((data_type *) gum_invocation_context_get_listener_thread_data (ctx, \
        sizeof (data_type)))
#define GUM_LINCTX_GET_FUNC_DATA(ctx, data_type) \
    ((data_type) gum_invocation_context_get_listener_function_data (ctx))
#define GUM_LINCTX_GET_FUNC_INVDATA(ctx, data_type) \
    ((data_type *) \
        gum_invocation_context_get_listener_function_invocation_data (ctx, \
            sizeof (data_type)))

#define GUM_RINCTX_GET_FUNC_DATA(ctx, data_type) \
    ((data_type) gum_invocation_context_get_replacement_function_data (ctx))

typedef struct _GumInvocationBackend GumInvocationBackend;
typedef struct _GumInvocationContext GumInvocationContext;

struct _GumInvocationBackend
{
  gpointer (* get_nth_argument) (GumInvocationContext * context, guint n);
  void (* replace_nth_argument) (GumInvocationContext * context, guint n,
      gpointer value);
  gpointer (* get_return_value) (GumInvocationContext * context);

  guint (* get_thread_id) (GumInvocationContext * context);

  gpointer (* get_listener_thread_data) (GumInvocationContext * context,
      gsize required_size);
  gpointer (* get_listener_function_data) (GumInvocationContext * context);
  gpointer (* get_listener_function_invocation_data) (
      GumInvocationContext * context, gsize required_size);

  gpointer (* get_replacement_function_data) (GumInvocationContext * context);

  gpointer user_data;
};

struct _GumInvocationContext
{
  GCallback function;
  GumCpuContext * cpu_context;

  /*< private */
  GumInvocationBackend * backend;
};

G_BEGIN_DECLS

GUM_API gpointer gum_invocation_context_get_nth_argument (
    GumInvocationContext * context, guint n);
GUM_API void gum_invocation_context_replace_nth_argument (
    GumInvocationContext * context, guint n, gpointer value);
GUM_API gpointer gum_invocation_context_get_return_value (
    GumInvocationContext * context);

GUM_API guint gum_invocation_context_get_thread_id (
    GumInvocationContext * context);

GUM_API gpointer gum_invocation_context_get_listener_thread_data (
    GumInvocationContext * context, gsize required_size);
GUM_API gpointer gum_invocation_context_get_listener_function_data (
    GumInvocationContext * context);
GUM_API gpointer gum_invocation_context_get_listener_function_invocation_data (
    GumInvocationContext * context, gsize required_size);

GUM_API gpointer gum_invocation_context_get_replacement_function_data (
    GumInvocationContext * context);

G_END_DECLS

#endif