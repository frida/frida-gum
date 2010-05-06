/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "interceptorharness.h"
#include <string.h>

static void listener_context_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (ListenerContext,
                        listener_context,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            listener_context_iface_init));

void
interceptor_harness_setup (InterceptorHarness * h)
{
  h->interceptor = gum_interceptor_obtain ();
  h->result = g_string_new ("");
  memset (&h->listener_context, 0, sizeof (h->listener_context));
}

void
interceptor_harness_teardown (InterceptorHarness * h)
{
  guint i;

  for (i = 0; i < G_N_ELEMENTS (h->listener_context); i++)
  {
    ListenerContext * ctx = h->listener_context[i];

    if (ctx != NULL)
    {
      gum_interceptor_detach_listener (h->interceptor,
          GUM_INVOCATION_LISTENER (ctx));
      g_object_unref (ctx);
    }
  }

  g_string_free (h->result, TRUE);
  g_object_unref (h->interceptor);
}

void
interceptor_harness_attach_listener (InterceptorHarness * h,
                                     guint listener_index,
                                     gpointer test_func,
                                     gchar enter_char,
                                     gchar leave_char)
{
  g_assert_cmpint (interceptor_harness_try_attaching_listener (h,
      listener_index, test_func, enter_char, leave_char), ==,
      GUM_ATTACH_OK);
}

GumAttachReturn
interceptor_harness_try_attaching_listener (InterceptorHarness * h,
                                            guint listener_index,
                                            gpointer test_func,
                                            gchar enter_char,
                                            gchar leave_char)
{
  GumAttachReturn result;
  ListenerContext * ctx;

  ctx = g_object_new (listener_context_get_type (), NULL);
  ctx->harness = h;
  ctx->enter_char = enter_char;
  ctx->leave_char = leave_char;

  result = gum_interceptor_attach_listener (h->interceptor, test_func,
      GUM_INVOCATION_LISTENER (ctx), NULL);
  if (result == GUM_ATTACH_OK)
  {
    h->listener_context[listener_index] = ctx;
  }
  else
  {
    g_object_unref (ctx);
  }

  return result;
}

void
interceptor_harness_detach_listener (InterceptorHarness * h,
                                     guint listener_index)
{
  gum_interceptor_detach_listener (h->interceptor,
    GUM_INVOCATION_LISTENER (h->listener_context[listener_index]));
}

static void
listener_context_on_enter (GumInvocationListener * listener,
                           GumInvocationContext * context,
                           GumInvocationContext * parent_context,
                           GumCpuContext * cpu_context,
                           gpointer function_arguments)
{
  ListenerContext * self = (ListenerContext *) listener;
  g_string_append_c (self->harness->result, self->enter_char);
  self->last_seen_argument =
      GPOINTER_TO_SIZE (*((gpointer *) function_arguments));
  self->last_on_enter_cpu_context = *cpu_context;
}

static void
listener_context_on_leave (GumInvocationListener * listener,
                           GumInvocationContext * context,
                           GumInvocationContext * parent_context,
                           gpointer function_return_value)
{
  ListenerContext * self = (ListenerContext *) listener;
  g_string_append_c (self->harness->result, self->leave_char);
  self->last_return_value = function_return_value;
}

static gpointer
listener_context_provide_thread_data (GumInvocationListener * listener,
                                      gpointer function_instance_data,
                                      guint thread_id)
{
  ListenerContext * self = (ListenerContext *) listener;
  self->last_thread_id = thread_id;
  return NULL;
}

static void
listener_context_class_init (ListenerContextClass * klass)
{
}

static void
listener_context_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = listener_context_on_enter;
  iface->on_leave = listener_context_on_leave;
  iface->provide_thread_data = listener_context_provide_thread_data;
}

static void
listener_context_init (ListenerContext * self)
{
}
