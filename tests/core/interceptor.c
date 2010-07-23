/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "interceptor-fixture.c"

#include "interceptor-callbacklistener.c"

#include <stdlib.h>

static gpointer target_function (GString * str);
static gpointer target_nop_function_a (gpointer data);
static gpointer target_nop_function_b (gpointer data);
static gpointer target_nop_function_c (gpointer data);
static gpointer replacement_malloc (gpointer original_impl, gpointer user_data,
    gpointer caller_ret_addr, guint size);

TEST_LIST_BEGIN (interceptor)
#if GLIB_SIZEOF_VOID_P == 4
  INTERCEPTOR_TESTENTRY (cpu_register_clobber)
  INTERCEPTOR_TESTENTRY (cpu_flag_clobber)
#endif

  INTERCEPTOR_TESTENTRY (i_can_has_attachability)
  INTERCEPTOR_TESTENTRY (already_attached)
#if GLIB_SIZEOF_VOID_P == 4
  INTERCEPTOR_TESTENTRY (relative_proxy_function)
#endif
  INTERCEPTOR_TESTENTRY (absolute_indirect_proxy_function)
  INTERCEPTOR_TESTENTRY (two_indirects_to_function)
#if GLIB_SIZEOF_VOID_P == 4
  INTERCEPTOR_TESTENTRY (relocation_of_early_call)
#endif

  INTERCEPTOR_TESTENTRY (attach_one)
  INTERCEPTOR_TESTENTRY (attach_two)
  INTERCEPTOR_TESTENTRY (attach_to_heap_api)
  /*INTERCEPTOR_TESTENTRY (attach_to_own_api)*/
  INTERCEPTOR_TESTENTRY (thread_id)
  INTERCEPTOR_TESTENTRY (intercepted_free_in_thread_exit)
  INTERCEPTOR_TESTENTRY (function_arguments)
  INTERCEPTOR_TESTENTRY (function_return_value)
#if GLIB_SIZEOF_VOID_P == 4
  INTERCEPTOR_TESTENTRY (function_cpu_context_on_enter)
#endif
  INTERCEPTOR_TESTENTRY (ignore_caller)
  INTERCEPTOR_TESTENTRY (ignore_caller_nested)
  INTERCEPTOR_TESTENTRY (detach)
  INTERCEPTOR_TESTENTRY (listener_ref_count)
  INTERCEPTOR_TESTENTRY (function_data)
  INTERCEPTOR_TESTENTRY (parent_data)

#if GLIB_SIZEOF_VOID_P == 4
  INTERCEPTOR_TESTENTRY (replace_function)
#endif
TEST_LIST_END ()

INTERCEPTOR_TESTCASE (attach_one)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

INTERCEPTOR_TESTCASE (attach_two)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, 'a', 'b');
  interceptor_fixture_attach_listener (fixture, 1, &target_function, 'c', 'd');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");
}

INTERCEPTOR_TESTCASE (attach_to_heap_api)
{
  void * p;

  interceptor_fixture_attach_listener (fixture, 0, &malloc, '>', '<');
  interceptor_fixture_attach_listener (fixture, 1, &free, 'a', 'b');
  p = malloc (1);
  free (p);
  g_assert_cmpstr (fixture->result->str, ==, "><ab");

  interceptor_fixture_detach_listener (fixture, 0);
  interceptor_fixture_detach_listener (fixture, 1);

  g_assert_cmpstr (fixture->result->str, ==, "><ab");
}

INTERCEPTOR_TESTCASE (attach_to_own_api)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  gum_interceptor_attach_listener (fixture->interceptor, target_function,
      GUM_INVOCATION_LISTENER (listener), NULL);
  target_function (fixture->result);
  gum_interceptor_detach_listener (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_object_unref (listener);
}

INTERCEPTOR_TESTCASE (thread_id)
{
  guint first_thread_id, second_thread_id;

  interceptor_fixture_attach_listener (fixture, 0, &target_function, 'a', 'b');

  target_function (fixture->result);
  first_thread_id = fixture->listener_context[0]->last_thread_id;

  g_thread_join (g_thread_create ((GThreadFunc) target_function,
      fixture->result, TRUE, NULL));
  second_thread_id = fixture->listener_context[0]->last_thread_id;

  g_assert_cmpuint (second_thread_id, !=, first_thread_id);
}

INTERCEPTOR_TESTCASE (intercepted_free_in_thread_exit)
{
  interceptor_fixture_attach_listener (fixture, 0, &free, 'a', 'b');
  g_thread_join (g_thread_create (target_nop_function_a, NULL, TRUE, NULL));
}

INTERCEPTOR_TESTCASE (function_arguments)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_nop_function_a, 'a',
      'b');
  target_nop_function_a (GSIZE_TO_POINTER (0x12349876));
  g_assert_cmphex (fixture->listener_context[0]->last_seen_argument,
      ==, 0x12349876);
}

INTERCEPTOR_TESTCASE (function_return_value)
{
  gpointer return_value;

  interceptor_fixture_attach_listener (fixture, 0, &target_nop_function_a, 'a',
      'b');
  return_value = target_nop_function_a (NULL);
  g_assert_cmphex (
      GPOINTER_TO_SIZE (fixture->listener_context[0]->last_return_value),
      ==, GPOINTER_TO_SIZE (return_value));
}

#if GLIB_SIZEOF_VOID_P == 4

INTERCEPTOR_TESTCASE (function_cpu_context_on_enter)
{
  GumCpuContext input, output, * ctx;

  interceptor_fixture_attach_listener (fixture, 0, &clobber_test_function, 'a',
      'b');

  input.edi = 0x1234a001;
  input.esi = 0x12340b02;
  input.ebp = 0x123400c3;
  input.ebx = 0x12340d04;
  input.edx = 0x1234e005;
  input.ecx = 0x12340f06;
  input.eax = 0x12340107;
  
  invoke_clobber_test_function_with_cpu_context (&input, &output);

  ctx = &fixture->listener_context[0]->last_on_enter_cpu_context;
  g_assert_cmphex (ctx->edi, ==, input.edi);
  g_assert_cmphex (ctx->esi, ==, input.esi);
  g_assert_cmphex (ctx->ebp, ==, input.ebp);
  g_assert_cmphex (ctx->ebx, ==, input.ebx);
  g_assert_cmphex (ctx->edx, ==, input.edx);
  g_assert_cmphex (ctx->ecx, ==, input.ecx);
  g_assert_cmphex (ctx->eax, ==, input.eax);
}

#endif

INTERCEPTOR_TESTCASE (ignore_caller)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, '>',
      '<');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  gum_interceptor_ignore_caller (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");

  gum_interceptor_unignore_caller (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

INTERCEPTOR_TESTCASE (ignore_caller_nested)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, '>',
      '<');

  gum_interceptor_ignore_caller (fixture->interceptor);
  gum_interceptor_ignore_caller (fixture->interceptor);
  gum_interceptor_unignore_caller (fixture->interceptor);
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");
  gum_interceptor_unignore_caller (fixture->interceptor);
}

INTERCEPTOR_TESTCASE (detach)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, 'a', 'b');
  interceptor_fixture_attach_listener (fixture, 1, &target_function, 'c', 'd');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");

  interceptor_fixture_detach_listener (fixture, 0);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "c|d");
}

INTERCEPTOR_TESTCASE (listener_ref_count)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, 'a', 'b');
  g_assert_cmpuint (G_OBJECT (fixture->listener_context[0])->ref_count, ==, 1);
}

#include "interceptor-functiondatalistener.c"

INTERCEPTOR_TESTCASE (function_data)
{
  TestFunctionDataListener * fd_listener;
  GumInvocationListener * listener;

  fd_listener = (TestFunctionDataListener *)
      g_object_new (TEST_TYPE_FUNCTION_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (fd_listener);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      &target_nop_function_a, listener, "a"), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      &target_nop_function_b, listener, "b"), ==, GUM_ATTACH_OK);

  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 0);

  target_nop_function_a (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.thread_data,
      ==, "a1");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.thread_data,
      ==, "a1");

  target_nop_function_a (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.thread_data,
      ==, "a1");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.thread_data,
      ==, "a1");

  test_function_data_listener_reset (fd_listener);

  target_nop_function_b (NULL);
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.instance_data,
      ==, "b");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.instance_data,
      ==, "b");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.thread_data,
      ==, "b1");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.thread_data,
      ==, "b1");

  test_function_data_listener_reset (fd_listener);

  g_thread_join (g_thread_create (target_nop_function_a, NULL, TRUE, NULL));
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->provide_thread_data_call_count, ==, 1);
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.instance_data,
      ==, "a");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_enter_ctx.thread_data,
      ==, "a2");
  g_assert_cmpstr ((gchar *) fd_listener->last_on_leave_ctx.thread_data,
      ==, "a2");

  gum_interceptor_detach_listener (fixture->interceptor, listener);
  g_object_unref (fd_listener);
}

#include "interceptor-parentdatalistener.c"

INTERCEPTOR_TESTCASE (parent_data)
{
  TestParentDataListener * pd_listener;
  GumInvocationListener * listener;

  pd_listener = g_object_new (TEST_TYPE_PARENT_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (pd_listener);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      &target_nop_function_c, listener, "c"), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
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

  gum_interceptor_detach_listener (fixture->interceptor, listener);
  g_object_unref (pd_listener);
}

#if GLIB_SIZEOF_VOID_P == 4

INTERCEPTOR_TESTCASE (cpu_register_clobber)
{
  GumCpuContext input, output;

  input.edi = 0x1234a001;
  input.esi = 0x12340b02;
  input.ebp = 0x123400c3;
  input.ebx = 0x12340d04;
  input.edx = 0x1234e005;
  input.ecx = 0x12340f06;
  input.eax = 0x12340107;

  interceptor_fixture_attach_listener (fixture, 0, &clobber_test_function,
      '>', '<');

  invoke_clobber_test_function_with_cpu_context (&input, &output);

  g_assert_cmphex (output.edi, ==, input.edi);
  g_assert_cmphex (output.esi, ==, input.esi);
  g_assert_cmphex (output.ebp, ==, input.ebp);
  g_assert_cmphex (output.ebx, ==, input.ebx);
  g_assert_cmphex (output.edx, ==, input.edx);
  g_assert_cmphex (output.ecx, ==, input.ecx);
  g_assert_cmphex (output.eax, ==, input.eax);
}

INTERCEPTOR_TESTCASE (cpu_flag_clobber)
{
  gsize flags_input, flags_output;

  interceptor_fixture_attach_listener (fixture, 0, clobber_test_function,
      '>', '<');

  invoke_clobber_test_function_with_carry_set (&flags_input, &flags_output);

  g_assert_cmphex (flags_output, ==, flags_input);
}

#endif

INTERCEPTOR_TESTCASE (i_can_has_attachability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;
  
  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (interceptor_fixture_try_attaching_listener (fixture, 0,
        func->code, '>', '<'), ==, GUM_ATTACH_WRONG_SIGNATURE);
  }
  
  unsupported_function_list_free (unsupported_functions);
}

INTERCEPTOR_TESTCASE (already_attached)
{
  interceptor_fixture_attach_listener (fixture, 0, &target_function, '>', '<');
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      &target_function, GUM_INVOCATION_LISTENER (fixture->listener_context[0]),
      NULL), ==, GUM_ATTACH_ALREADY_ATTACHED);
}

#if GLIB_SIZEOF_VOID_P == 4

INTERCEPTOR_TESTCASE (relative_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_relative_with_target (&target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

#endif

INTERCEPTOR_TESTCASE (absolute_indirect_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_absolute_indirect_with_target (&target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

INTERCEPTOR_TESTCASE (two_indirects_to_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_two_jumps_with_target (&target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

#if GLIB_SIZEOF_VOID_P == 4

INTERCEPTOR_TESTCASE (relocation_of_early_call)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_early_call_with_target (&target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach_listener (fixture, 0);

  proxy_func_free (proxy_func);
}

INTERCEPTOR_TESTCASE (replace_function)
{
  guint counter = 0;
  gpointer ret;

  gum_interceptor_replace_function (fixture->interceptor,
      malloc, replacement_malloc, &counter);
  ret = malloc (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert_function().  We do the real assert after reverting,
   * as failing asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert (ret != NULL);

  gum_interceptor_revert_function (fixture->interceptor, malloc);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), ==, 0x42);
  g_assert_cmpint (counter, ==, 1);

  ret = malloc (1);
  g_assert_cmpint (counter, ==, 1);
  free (ret);
}

#endif

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
  MallocFunction malloc_impl = (MallocFunction) original_impl;
  guint * counter = (guint *) user_data;
  gpointer a;

  (*counter)++;

  a = malloc_impl (1);
  free (a);

  return GSIZE_TO_POINTER (size);
}
