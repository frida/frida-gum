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

#ifndef __INTERCEPTOR_HARNESS_H__
#define __INTERCEPTOR_HARNESS_H__

#include <gum/guminterceptor.h>

typedef struct _InterceptorHarness   InterceptorHarness;
typedef struct _ListenerContext      ListenerContext;
typedef struct _ListenerContextClass ListenerContextClass;

typedef gpointer (* InterceptorTestFunc) (gpointer data);

struct _ListenerContext
{
  GObject parent;

  InterceptorHarness * harness;
  gchar enter_char;
  gchar leave_char;
  guint last_thread_id;
  gsize last_seen_argument;
  gpointer last_return_value;
  GumCpuContext last_on_enter_cpu_context;
};

struct _ListenerContextClass
{
  GObjectClass parent_class;
};

struct _InterceptorHarness
{
  GumInterceptor * interceptor;
  GString * result;
  ListenerContext * listener_context[2];
};

G_BEGIN_DECLS

void interceptor_harness_setup (InterceptorHarness * h);
void interceptor_harness_teardown (InterceptorHarness * h);

void interceptor_harness_attach_listener (InterceptorHarness * h,
    guint listener_index, gpointer test_func, gchar enter_char,
    gchar leave_char);
GumAttachReturn interceptor_harness_try_attaching_listener (
    InterceptorHarness * h, guint listener_index, gpointer test_func,
    gchar enter_char, gchar leave_char);
void interceptor_harness_detach_listener (InterceptorHarness * h,
    guint listener_index);

G_END_DECLS

#endif
