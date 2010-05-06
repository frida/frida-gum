/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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
#include "interceptor-lowlevel.h"
#include <stdlib.h>
#include <string.h>

static gpointer target_function (GString * str);
static gpointer target_nop_function_a (gpointer data);
static gpointer target_nop_function_b (gpointer data);
static gpointer target_nop_function_c (gpointer data);
static gpointer replacement_malloc (gpointer original_impl, gpointer user_data,
    gpointer caller_ret_addr, guint size);

static void
test_attach_one (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, '>', '<');
  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  interceptor_harness_teardown (&h);
}

static void
test_attach_two (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, 'a', 'b');
  interceptor_harness_attach_listener (&h, 1, &target_function, 'c', 'd');
  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, "ac|bd");

  interceptor_harness_teardown (&h);
}

static void
test_attach_to_dependent_api (void)
{
  InterceptorHarness h;
  void * p;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &malloc, '>', '<');
  interceptor_harness_attach_listener (&h, 1, &free, 'a', 'b');
  p = malloc (1);
  free (p);
  g_assert_cmpstr (h.result->str, ==, "><ab");

  interceptor_harness_detach_listener (&h, 0);
  interceptor_harness_detach_listener (&h, 1);

  g_assert_cmpstr (h.result->str, ==, "><ab");

  interceptor_harness_teardown (&h);
}

static void
test_thread_id (void)
{
  InterceptorHarness h;
  guint first_thread_id, second_thread_id;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, 'a', 'b');

  target_function (h.result);
  first_thread_id = h.listener_context[0]->last_thread_id;

  g_thread_join (g_thread_create ((GThreadFunc) target_function, h.result,
      TRUE, NULL));
  second_thread_id = h.listener_context[0]->last_thread_id;

  g_assert_cmpuint (second_thread_id, !=, first_thread_id);

  interceptor_harness_teardown (&h);
}

static void
test_intercepted_free_in_thread_exit (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &free, 'a', 'b');
  g_thread_join (g_thread_create (target_nop_function_a, NULL, TRUE, NULL));

  interceptor_harness_teardown (&h);
}

static void
test_function_arguments (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_nop_function_a, 'a',
      'b');
  target_nop_function_a (GSIZE_TO_POINTER (0x12349876));
  g_assert_cmphex (h.listener_context[0]->last_seen_argument, ==, 0x12349876);

  interceptor_harness_teardown (&h);
}

static void
test_function_return_value (void)
{
  InterceptorHarness h;
  gpointer return_value;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_nop_function_a, 'a',
      'b');
  return_value = target_nop_function_a (NULL);
  g_assert_cmphex (GPOINTER_TO_SIZE (h.listener_context[0]->last_return_value),
      ==, GPOINTER_TO_SIZE (return_value));

  interceptor_harness_teardown (&h);
}

#if GLIB_SIZEOF_VOID_P == 4
static void
test_function_cpu_context_on_enter (void)
{
  InterceptorHarness h;
  GumCpuContext input, output, * ctx;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &clobber_test_function, 'a',
      'b');

  input.edi = 0x1234a001;
  input.esi = 0x12340b02;
  input.ebp = 0x123400c3;
  input.ebx = 0x12340d04;
  input.edx = 0x1234e005;
  input.ecx = 0x12340f06;
  input.eax = 0x12340107;
  
  invoke_clobber_test_function_with_cpu_context (&input, &output);

  ctx = &h.listener_context[0]->last_on_enter_cpu_context;
  g_assert_cmphex (ctx->edi, ==, input.edi);
  g_assert_cmphex (ctx->esi, ==, input.esi);
  g_assert_cmphex (ctx->ebp, ==, input.ebp);
  g_assert_cmphex (ctx->ebx, ==, input.ebx);
  g_assert_cmphex (ctx->edx, ==, input.edx);
  g_assert_cmphex (ctx->ecx, ==, input.ecx);
  g_assert_cmphex (ctx->eax, ==, input.eax);

  interceptor_harness_teardown (&h);
}
#endif

static void
test_ignore_caller (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, '>',
      '<');

  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  gum_interceptor_ignore_caller (h.interceptor);
  g_string_truncate (h.result, 0);

  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, "|");

  gum_interceptor_unignore_caller (h.interceptor);
  g_string_truncate (h.result, 0);

  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  interceptor_harness_teardown (&h);
}

/* FIXME: ignore_caller()/unignore_caller() need better names */
static void
test_ignore_caller_nested (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, '>',
      '<');

  gum_interceptor_ignore_caller (h.interceptor);
  gum_interceptor_ignore_caller (h.interceptor);
  gum_interceptor_unignore_caller (h.interceptor);
  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, "|");
  gum_interceptor_unignore_caller (h.interceptor);

  interceptor_harness_teardown (&h);
}

static void
test_detach (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, 'a', 'b');
  interceptor_harness_attach_listener (&h, 1, &target_function, 'c', 'd');

  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, "ac|bd");

  interceptor_harness_detach_listener (&h, 0);
  g_string_truncate (h.result, 0);

  target_function (h.result);
  g_assert_cmpstr (h.result->str, ==, "c|d");

  interceptor_harness_teardown (&h);
}

static void
test_listener_ref_count (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, 'a', 'b');
  g_assert_cmpuint (G_OBJECT (h.listener_context[0])->ref_count, ==, 1);

  interceptor_harness_teardown (&h);
}

typedef struct {
  GObject parent;
  guint on_enter_call_count;
  guint on_leave_call_count;
  guint provide_thread_data_call_count;
  GumInvocationContext last_on_enter_ctx;
  GumInvocationContext last_on_leave_ctx;
  GSList * a_threads_seen;
  guint a_thread_index;
  GSList * b_threads_seen;
  guint b_thread_index;
  GSList * provided_thread_data;
} TestFunctionDataListener;

typedef struct {
  GObjectClass parent_class;
} TestFunctionDataListenerClass;

#define TEST_TYPE_FUNCTION_DATA_LISTENER \
    (test_function_data_listener_get_type ())
#define TEST_FUNCTION_DATA_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    TEST_TYPE_FUNCTION_DATA_LISTENER, TestFunctionDataListener))

static void test_function_data_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void test_function_data_listener_finalize (GObject * object);

G_DEFINE_TYPE_EXTENDED (TestFunctionDataListener,
                        test_function_data_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            test_function_data_listener_iface_init));

static void
test_function_data_listener_on_enter (GumInvocationListener * listener,
                                      GumInvocationContext * context,
                                      GumInvocationContext * parent_context,
                                      GumCpuContext * cpu_context,
                                      gpointer function_arguments)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);

  self->on_enter_call_count++;
  self->last_on_enter_ctx = *context;
}

static void
test_function_data_listener_on_leave (GumInvocationListener * listener,
                                      GumInvocationContext * context,
                                      GumInvocationContext * parent_context,
                                      gpointer function_return_value)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);

  self->on_leave_call_count++;
  self->last_on_leave_ctx = *context;
}

static gpointer
test_context_provide_thread_data (GumInvocationListener * listener,
                                  gpointer function_instance_data,
                                  guint thread_id)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);
  GSList ** threads_seen;
  guint * thread_index;
  GThread * cur_thread;
  gchar * thread_data;

  self->provide_thread_data_call_count++;

  if (strcmp (function_instance_data, "a") == 0)
  {
    threads_seen = &self->a_threads_seen;
    thread_index = &self->a_thread_index;
  }
  else if (strcmp (function_instance_data, "b") == 0)
  {
    threads_seen = &self->b_threads_seen;
    thread_index = &self->b_thread_index;
  }
  else
    g_assert_not_reached ();

  cur_thread = g_thread_self ();
  if (g_slist_find (*threads_seen, cur_thread) == NULL)
  {
    *threads_seen = g_slist_prepend (*threads_seen, cur_thread);
    (*thread_index)++;
  }

  thread_data =
      g_strdup_printf ("%s%d", (gchar *) function_instance_data, *thread_index);
  self->provided_thread_data = g_slist_prepend (self->provided_thread_data,
      thread_data);
  return thread_data;
}

static void
test_function_data_listener_iface_init (gpointer g_iface,
                                        gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = test_function_data_listener_on_enter;
  iface->on_leave = test_function_data_listener_on_leave;
  iface->provide_thread_data = test_context_provide_thread_data;
}

static void
test_function_data_listener_class_init (TestFunctionDataListenerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = test_function_data_listener_finalize;
}

static void
test_function_data_listener_init (TestFunctionDataListener * self)
{
}

static void
test_function_data_listener_finalize (GObject * object)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (object);

  while (self->provided_thread_data != NULL)
  {
    gchar * entry = self->provided_thread_data->data;
    self->provided_thread_data = g_slist_remove (self->provided_thread_data,
        entry);
    g_free (entry);
  }

  G_OBJECT_CLASS (test_function_data_listener_parent_class)->finalize (object);
}

static void
test_function_data_listener_reset (TestFunctionDataListener * self)
{
  self->on_enter_call_count = 0;
  self->on_leave_call_count = 0;
  self->provide_thread_data_call_count = 0;
  memset (&self->last_on_enter_ctx, 0, sizeof (GumInvocationContext));
  memset (&self->last_on_leave_ctx, 0, sizeof (GumInvocationContext));
}

static void
test_function_data (void)
{
  GumInterceptor * interceptor;
  TestFunctionDataListener * fd_listener;
  GumInvocationListener * listener;

  interceptor = gum_interceptor_obtain ();
  fd_listener = g_object_new (TEST_TYPE_FUNCTION_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (fd_listener);
  g_assert_cmpint (gum_interceptor_attach_listener (interceptor,
      &target_nop_function_a, listener, "a"), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach_listener (interceptor,
      &target_nop_function_b, listener, "b"), ==, GUM_ATTACH_OK);

  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 0);

  target_nop_function_a (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.thread_data, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.thread_data, ==, "a1");

  target_nop_function_a (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.thread_data, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.thread_data, ==, "a1");

  test_function_data_listener_reset (fd_listener);

  target_nop_function_b (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.instance_data, ==, "b");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.instance_data, ==, "b");
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.thread_data, ==, "b1");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.thread_data, ==, "b1");

  test_function_data_listener_reset (fd_listener);

  g_thread_join (g_thread_create (target_nop_function_a, NULL, TRUE, NULL));
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.instance_data, ==, "a");
  g_assert_cmpstr (fd_listener->last_on_enter_ctx.thread_data, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_leave_ctx.thread_data, ==, "a2");

  gum_interceptor_detach_listener (interceptor, listener);
  g_object_unref (fd_listener);
  g_object_unref (interceptor);
}

typedef struct {
  GObject parent;
  GumInvocationContext a_on_enter_parent_ctx;
  GumInvocationContext a_on_leave_parent_ctx;
  GumInvocationContext c_on_enter_parent_ctx;
  GumInvocationContext c_on_leave_parent_ctx;
} TestParentDataListener;

typedef struct {
  GObjectClass parent_class;
} TestParentDataListenerClass;

#define TEST_TYPE_PARENT_DATA_LISTENER \
    (test_parent_data_listener_get_type ())
#define TEST_PARENT_DATA_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    TEST_TYPE_PARENT_DATA_LISTENER, TestParentDataListener))

static void test_parent_data_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (TestParentDataListener,
                        test_parent_data_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            test_parent_data_listener_iface_init));

static void
test_parent_data_listener_on_enter (GumInvocationListener * listener,
                                    GumInvocationContext * context,
                                    GumInvocationContext * parent_context,
                                    GumCpuContext * cpu_context,
                                    gpointer function_arguments)
{
  TestParentDataListener * self = TEST_PARENT_DATA_LISTENER (listener);

  if (strcmp (context->instance_data, "a") == 0)
    self->a_on_enter_parent_ctx = *parent_context;
  else if (strcmp (context->instance_data, "c") == 0)
    self->c_on_enter_parent_ctx = *parent_context;
}

static void
test_parent_data_listener_on_leave (GumInvocationListener * listener,
                                    GumInvocationContext * context,
                                    GumInvocationContext * parent_context,
                                    gpointer function_return_value)
{
  TestParentDataListener * self = TEST_PARENT_DATA_LISTENER (listener);

  if (strcmp (context->instance_data, "a") == 0)
    self->a_on_leave_parent_ctx = *parent_context;
  else if (strcmp (context->instance_data, "c") == 0)
    self->c_on_leave_parent_ctx = *parent_context;
}

static gpointer
test_parent_data_listener_provide_thread_data (GumInvocationListener * listener,
                                               gpointer function_instance_data,
                                               guint thread_id)
{
  if (strcmp (function_instance_data, "a") == 0)
    return "a1";
  else if (strcmp (function_instance_data, "c") == 0)
    return "c1";
  else
    g_assert_not_reached ();

  return NULL;
}

static void
test_parent_data_listener_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = test_parent_data_listener_on_enter;
  iface->on_leave = test_parent_data_listener_on_leave;
  iface->provide_thread_data = test_parent_data_listener_provide_thread_data;
}

static void
test_parent_data_listener_class_init (TestParentDataListenerClass * klass)
{
}

static void
test_parent_data_listener_init (TestParentDataListener * self)
{
}

static void
test_parent_data (void)
{
  GumInterceptor * interceptor;
  TestParentDataListener * pd_listener;
  GumInvocationListener * listener;

  interceptor = gum_interceptor_obtain ();
  pd_listener = g_object_new (TEST_TYPE_PARENT_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (pd_listener);
  g_assert_cmpint (gum_interceptor_attach_listener (interceptor,
      &target_nop_function_c, listener, "c"), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach_listener (interceptor,
      &target_nop_function_a, listener, "a"), ==, GUM_ATTACH_OK);

  target_nop_function_c (NULL);

  g_assert_cmpstr (pd_listener->a_on_enter_parent_ctx.instance_data, ==, "c");
  g_assert_cmpstr (pd_listener->a_on_enter_parent_ctx.thread_data,   ==, "c1");
  g_assert_cmpstr (pd_listener->a_on_leave_parent_ctx.instance_data, ==, "c");
  g_assert_cmpstr (pd_listener->a_on_leave_parent_ctx.thread_data,   ==, "c1");

  g_assert (pd_listener->c_on_enter_parent_ctx.instance_data == NULL);
  g_assert (pd_listener->c_on_enter_parent_ctx.thread_data   == NULL);
  g_assert (pd_listener->c_on_leave_parent_ctx.instance_data == NULL);
  g_assert (pd_listener->c_on_leave_parent_ctx.thread_data   == NULL);

  gum_interceptor_detach_listener (interceptor, listener);
  g_object_unref (pd_listener);
  g_object_unref (interceptor);
}

#if GLIB_SIZEOF_VOID_P == 4
static void
test_cpu_register_clobber (void)
{
  InterceptorHarness h;
  GumCpuContext input, output;

  input.edi = 0x1234a001;
  input.esi = 0x12340b02;
  input.ebp = 0x123400c3;
  input.ebx = 0x12340d04;
  input.edx = 0x1234e005;
  input.ecx = 0x12340f06;
  input.eax = 0x12340107;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &clobber_test_function, '>', '<');

  invoke_clobber_test_function_with_cpu_context (&input, &output);

  g_assert_cmphex (output.edi, ==, input.edi);
  g_assert_cmphex (output.esi, ==, input.esi);
  g_assert_cmphex (output.ebp, ==, input.ebp);
  g_assert_cmphex (output.ebx, ==, input.ebx);
  g_assert_cmphex (output.edx, ==, input.edx);
  g_assert_cmphex (output.ecx, ==, input.ecx);
  g_assert_cmphex (output.eax, ==, input.eax);

  interceptor_harness_teardown (&h);
}

static void
test_cpu_flag_clobber (void)
{
  InterceptorHarness h;
  gsize flags_input, flags_output;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, clobber_test_function, '>', '<');

  invoke_clobber_test_function_with_carry_set (&flags_input, &flags_output);

  g_assert_cmphex (flags_output, ==, flags_input);

  interceptor_harness_teardown (&h);
}
#endif

static void
test_i_can_has_attachability (void)
{
  InterceptorHarness h;
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  interceptor_harness_setup (&h);
  
  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (interceptor_harness_try_attaching_listener (&h, 0,
        func->code, '>', '<'), ==, GUM_ATTACH_WRONG_SIGNATURE);
  }
  
  unsupported_function_list_free (unsupported_functions);

  interceptor_harness_teardown (&h);
}

static void
test_already_attached (void)
{
  InterceptorHarness h;

  interceptor_harness_setup (&h);

  interceptor_harness_attach_listener (&h, 0, &target_function, '>', '<');
  g_assert_cmpint (gum_interceptor_attach_listener (h.interceptor,
      &target_function, GUM_INVOCATION_LISTENER (h.listener_context[0]), NULL),
      ==, GUM_ATTACH_ALREADY_ATTACHED);

  interceptor_harness_teardown (&h);
}

#if GLIB_SIZEOF_VOID_P == 4

static void
test_relative_proxy_function (void)
{
  InterceptorHarness h;
  ProxyFunc proxy_func;

  interceptor_harness_setup (&h);

  proxy_func = proxy_func_new_relative_with_target (&target_function);

  interceptor_harness_attach_listener (&h, 0, proxy_func, '>', '<');
  proxy_func (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  proxy_func_free (proxy_func);

  interceptor_harness_teardown (&h);
}

#endif

static void
test_absolute_indirect_proxy_function (void)
{
  InterceptorHarness h;
  ProxyFunc proxy_func;

  interceptor_harness_setup (&h);

  proxy_func = proxy_func_new_absolute_indirect_with_target (&target_function);

  interceptor_harness_attach_listener (&h, 0, proxy_func, '>', '<');
  proxy_func (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  proxy_func_free (proxy_func);

  interceptor_harness_teardown (&h);
}

static void
test_two_indirects_to_function (void)
{
  InterceptorHarness h;
  ProxyFunc proxy_func;

  interceptor_harness_setup (&h);

  proxy_func = proxy_func_new_two_jumps_with_target (&target_function);

  interceptor_harness_attach_listener (&h, 0, proxy_func, '>', '<');
  proxy_func (h.result);
  g_assert_cmpstr (h.result->str, ==, ">|<");

  proxy_func_free (proxy_func);

  interceptor_harness_teardown (&h);
}

static void
test_replace_function (void)
{
  GumInterceptor * interceptor;
  guint counter = 0;
  gpointer ret;

  interceptor = gum_interceptor_obtain ();

  gum_interceptor_replace_function (interceptor, malloc, replacement_malloc,
      &counter);
  ret = malloc (0x42);

  gum_interceptor_revert_function (interceptor, malloc);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), ==, 0x42);
  g_assert_cmpint (counter, ==, 1);

  ret = malloc (1);
  g_assert_cmpint (counter, ==, 1);
  free (ret);

  g_object_unref (interceptor);
}

static gpointer GUM_NOINLINE
target_function (GString * str)
{
  g_string_append_c (str, '|');
  return NULL;
}

static guint counter = 0;

static gpointer GUM_NOINLINE
target_nop_function_a (gpointer data)
{
  counter++;
  return GSIZE_TO_POINTER (0x1337);
}

static gpointer GUM_NOINLINE
target_nop_function_b (gpointer data)
{
  counter += 2;
  return GSIZE_TO_POINTER (2);
}

static gpointer GUM_NOINLINE
target_nop_function_c (gpointer data)
{
  counter += 3;
  target_nop_function_a (data);
  return GSIZE_TO_POINTER (3);
}

typedef gpointer (* MallocFunction) (guint size);

static gpointer GUM_NOINLINE
replacement_malloc (gpointer original_impl,
                    gpointer user_data,
                    gpointer caller_ret_addr,
                    guint size)
{
  MallocFunction malloc_impl = original_impl;
  guint * counter = user_data;
  gpointer a;

  (*counter)++;

  a = malloc_impl (1);
  free (a);

  return GSIZE_TO_POINTER (size);
}

void
gum_test_register_interceptor_tests (void)
{
#if GLIB_SIZEOF_VOID_P == 4
  g_test_add_func ("/Gum/Interceptor/test-cpu-register-clobber",
      &test_cpu_register_clobber);
  g_test_add_func ("/Gum/Interceptor/test-cpu-flag-clobber",
      &test_cpu_flag_clobber);
#endif

  g_test_add_func ("/Gum/Interceptor/test-i-can-has-attachability",
      &test_i_can_has_attachability);
  g_test_add_func ("/Gum/Interceptor/test-already-attached",
      &test_already_attached);
#if GLIB_SIZEOF_VOID_P == 4
  g_test_add_func ("/Gum/Interceptor/test-relative-proxy-function",
      &test_relative_proxy_function);
#endif
  g_test_add_func ("/Gum/Interceptor/test-absolute-indirect-proxy-function",
      &test_absolute_indirect_proxy_function);
  g_test_add_func ("/Gum/Interceptor/test-two-indirects-to-function",
      &test_two_indirects_to_function);

  g_test_add_func ("/Gum/Interceptor/test-attach-one", &test_attach_one);
  g_test_add_func ("/Gum/Interceptor/test-attach-two", &test_attach_two);
  g_test_add_func ("/Gum/Interceptor/test-attach-to-dependent-api",
      &test_attach_to_dependent_api);
  g_test_add_func ("/Gum/Interceptor/test-thread-id", &test_thread_id);
  g_test_add_func ("/Gum/Interceptor/test-intercepted-free-in-thread-exit",
      &test_intercepted_free_in_thread_exit);
  g_test_add_func ("/Gum/Interceptor/test-function-arguments",
      &test_function_arguments);
  g_test_add_func ("/Gum/Interceptor/test-function-return-value",
      &test_function_return_value);
#if GLIB_SIZEOF_VOID_P == 4
  g_test_add_func ("/Gum/Interceptor/test-function-cpu-context-on-enter",
      &test_function_cpu_context_on_enter);
#endif
  g_test_add_func ("/Gum/Interceptor/test-ignore-caller", &test_ignore_caller);
  g_test_add_func ("/Gum/Interceptor/test-ignore-caller-nested",
      &test_ignore_caller_nested);
  g_test_add_func ("/Gum/Interceptor/test-detach", &test_detach);
  g_test_add_func ("/Gum/Interceptor/test-listener-ref-count",
      &test_listener_ref_count);
  g_test_add_func ("/Gum/Interceptor/test-function-data", &test_function_data);
  g_test_add_func ("/Gum/Interceptor/test-parent-data", &test_parent_data);

  g_test_add_func ("/Gum/Interceptor/test-replace-function",
      &test_replace_function);
}
