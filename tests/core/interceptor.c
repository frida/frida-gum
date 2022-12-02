/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-fixture.c"

TESTLIST_BEGIN (interceptor)
  TESTENTRY (cpu_register_clobber)
  TESTENTRY (cpu_flag_clobber)

  TESTENTRY (i_can_has_attachability)
#ifdef HAVE_I386
  TESTENTRY (already_attached)
  TESTENTRY (relative_proxy_function)
  TESTENTRY (absolute_indirect_proxy_function)
  TESTENTRY (two_indirects_to_function)
  TESTENTRY (relocation_of_early_call)
# if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (relocation_of_early_rip_relative_call)
# endif
#endif

  TESTENTRY (attach_one)
  TESTENTRY (attach_two)
  TESTENTRY (attach_to_recursive_function)
  TESTENTRY (attach_to_special_function)
#ifdef G_OS_UNIX
  TESTENTRY (attach_to_pthread_key_create)
#endif
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTENTRY (attach_to_heap_api)
#endif
  TESTENTRY (attach_to_own_api)
#ifdef HAVE_WINDOWS
  TESTENTRY (attach_detach_torture)
#endif
  TESTENTRY (thread_id)
#if defined (HAVE_FRIDA_GLIB) && \
    !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && \
    !defined (HAVE_ASAN)
  TESTENTRY (intercepted_free_in_thread_exit)
#endif
  TESTENTRY (function_arguments)
  TESTENTRY (function_return_value)
  TESTENTRY (function_cpu_context_on_enter)
  TESTENTRY (ignore_current_thread)
  TESTENTRY (ignore_current_thread_nested)
  TESTENTRY (ignore_other_threads)
  TESTENTRY (detach)
  TESTENTRY (listener_ref_count)
  TESTENTRY (function_data)

  TESTENTRY (i_can_has_replaceability)
  TESTENTRY (already_replaced)
#ifndef HAVE_ASAN
  TESTENTRY (replace_one)
# ifdef HAVE_FRIDA_GLIB
  TESTENTRY (replace_two)
# endif
#endif
  TESTENTRY (replace_then_attach)
  TESTENTRY (replace_keep_original)

  TESTENTRY (replace_then_replace_fast)
  TESTENTRY (attach_then_replace_fast)
  TESTENTRY (replace_fast_then_replace)
  TESTENTRY (replace_fast_then_attach)
  TESTENTRY (i_can_has_replaceability_fast)
  TESTENTRY (replace_one_fast)
  TESTENTRY (fast_interceptor_performance)
TESTLIST_END ()

#ifdef HAVE_WINDOWS
static gpointer hit_target_function_repeatedly (gpointer data);
#endif
static gpointer replacement_malloc (gsize size);
static gpointer replacement_target_function (GString * str);
static gpointer (* target_function_fast) (GString * str) = NULL;
static gpointer replacement_target_function_fast (GString * str);

TESTCASE (attach_one)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

TESTCASE (attach_two)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach (fixture, 1, target_function, 'c', 'd');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");
}

void GUM_NOINLINE
recursive_function (GString * str,
                    gint count)
{
  if (count > 0)
    recursive_function (str, count - 1);

  g_string_append_printf (str, "%d", count);
}

TESTCASE (attach_to_recursive_function)
{
  interceptor_fixture_attach (fixture, 0, recursive_function, '>', '<');
  recursive_function (fixture->result, 4);
  g_assert_cmpstr (fixture->result->str, ==, ">>>>>0<1<2<3<4<");
}

TESTCASE (attach_to_special_function)
{
  interceptor_fixture_attach (fixture, 0, special_function, '>', '<');
  special_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

#ifdef G_OS_UNIX

TESTCASE (attach_to_pthread_key_create)
{
  int (* pthread_key_create_impl) (pthread_key_t * key,
      void (* destructor) (void *));
  pthread_key_t key;

  pthread_key_create_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name (NULL, "pthread_key_create"));

  interceptor_fixture_attach (fixture, 0, pthread_key_create_impl, '>', '<');

  g_assert_cmpint (pthread_key_create_impl (&key, NULL), ==, 0);

  pthread_key_delete (key);
}

#endif

TESTCASE (attach_to_heap_api)
{
  gpointer malloc_impl, free_impl;
  volatile gpointer p;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();
  free_impl = interceptor_fixture_get_libc_free ();

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  interceptor_fixture_attach (fixture, 0, malloc_impl, '>', '<');
  interceptor_fixture_attach (fixture, 1, free_impl, 'a', 'b');
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  p = malloc (1);
  free (p);
  g_assert_cmpstr (fixture->result->str, ==, "><ab");

  interceptor_fixture_detach (fixture, 0);
  interceptor_fixture_detach (fixture, 1);

  g_assert_cmpstr (fixture->result->str, ==, "><ab");
}

TESTCASE (attach_to_own_api)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  gum_interceptor_attach (fixture->interceptor, target_function,
      GUM_INVOCATION_LISTENER (listener), NULL);
  target_function (fixture->result);
  gum_interceptor_detach (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_assert_cmpstr (fixture->result->str, ==, "|||");

  g_object_unref (listener);
}

#ifdef HAVE_WINDOWS

TESTCASE (attach_detach_torture)
{
  GThread * th;
  volatile guint n_passes = 100;

  th = g_thread_new ("interceptor-test-torture",
      hit_target_function_repeatedly, (gpointer) &n_passes);

  g_thread_yield ();

  do
  {
    TestCallbackListener * listener;

    interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');

    listener = test_callback_listener_new ();

    gum_interceptor_attach (fixture->interceptor, target_function,
        GUM_INVOCATION_LISTENER (listener), NULL);
    gum_interceptor_detach (fixture->interceptor,
        GUM_INVOCATION_LISTENER (listener));
    interceptor_fixture_detach (fixture, 0);

    g_object_unref (listener);
  }
  while (--n_passes != 0);

  g_thread_join (th);
}

#endif

TESTCASE (thread_id)
{
  GumThreadId first_thread_id, second_thread_id;

  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');

  target_function (fixture->result);
  first_thread_id = fixture->listener_context[0]->last_thread_id;

  g_thread_join (g_thread_new ("interceptor-test-thread-id",
      (GThreadFunc) target_function, fixture->result));
  second_thread_id = fixture->listener_context[0]->last_thread_id;

  g_assert_cmpuint (second_thread_id, !=, first_thread_id);
}

#if defined (HAVE_FRIDA_GLIB) && \
    !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && \
    !defined (HAVE_ASAN)

TESTCASE (intercepted_free_in_thread_exit)
{
  interceptor_fixture_attach (fixture, 0, interceptor_fixture_get_libc_free (),
      'a', 'b');
  g_thread_join (g_thread_new ("interceptor-test-thread-exit",
      target_nop_function_a, NULL));
}

#endif

TESTCASE (function_arguments)
{
  interceptor_fixture_attach (fixture, 0, target_nop_function_a, 'a', 'b');
  target_nop_function_a (GSIZE_TO_POINTER (0x12349876));
  g_assert_cmphex (fixture->listener_context[0]->last_seen_argument,
      ==, 0x12349876);
}

TESTCASE (function_return_value)
{
  gpointer return_value;

  interceptor_fixture_attach (fixture, 0, target_nop_function_a, 'a', 'b');
  return_value = target_nop_function_a (NULL);
  g_assert_cmphex (
      GPOINTER_TO_SIZE (fixture->listener_context[0]->last_return_value),
      ==, GPOINTER_TO_SIZE (return_value));
}

TESTCASE (function_cpu_context_on_enter)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    GumCpuContext input, output;

    interceptor_fixture_attach (fixture, 0, target_func, 'a', 'b');

    fill_cpu_context_with_magic_values (&input);
    invoke_clobber_test_function_with_cpu_context (target_func,
        &input, &output);
    g_assert_cmpstr (fixture->result->str, ==, "ab");
    assert_cpu_contexts_are_equal (&input,
        &fixture->listener_context[0]->last_on_enter_cpu_context);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (ignore_current_thread)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");

  gum_interceptor_unignore_current_thread (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

TESTCASE (ignore_current_thread_nested)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");
  gum_interceptor_unignore_current_thread (fixture->interceptor);
}

TESTCASE (ignore_other_threads)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  gum_interceptor_ignore_other_threads (fixture->interceptor);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  g_thread_join (g_thread_new ("interceptor-test-ignore-others-a",
      (GThreadFunc) target_function, fixture->result));
  g_assert_cmpstr (fixture->result->str, ==, ">|<|");

  gum_interceptor_unignore_other_threads (fixture->interceptor);

  g_thread_join (g_thread_new ("interceptor-test-ignore-others-b",
      (GThreadFunc) target_function, fixture->result));
  g_assert_cmpstr (fixture->result->str, ==, ">|<|>|<");
}

TESTCASE (detach)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach (fixture, 1, target_function, 'c', 'd');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");

  interceptor_fixture_detach (fixture, 0);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "c|d");
}

TESTCASE (listener_ref_count)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  g_assert_cmpuint (
      G_OBJECT (fixture->listener_context[0]->listener)->ref_count, ==, 1);
}

TESTCASE (function_data)
{
  TestFunctionDataListener * fd_listener;
  GumInvocationListener * listener;
  gpointer a_data = "a", b_data = "b";

  fd_listener =
      g_object_new (TEST_TYPE_FUNCTION_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (fd_listener);
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_nop_function_a, listener, a_data), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_nop_function_b, listener, b_data), ==, GUM_ATTACH_OK);

  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 0);

  target_nop_function_a ("badger");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "badger");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "badger");

  target_nop_function_a ("snake");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "snake");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "snake");

  test_function_data_listener_reset (fd_listener);

  target_nop_function_b ("mushroom");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 0);
  g_assert_true (fd_listener->last_on_enter_data.function_data == b_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == b_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "mushroom");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "mushroom");

  test_function_data_listener_reset (fd_listener);

  g_thread_join (g_thread_new ("interceptor-test-function-data",
      target_nop_function_a, "bdgr"));
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "bdgr");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "bdgr");

  gum_interceptor_detach (fixture->interceptor, listener);
  g_object_unref (fd_listener);
}

TESTCASE (cpu_register_clobber)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    GumCpuContext input, output;

    interceptor_fixture_attach (fixture, 0, target_func, '>', '<');

    fill_cpu_context_with_magic_values (&input);
    invoke_clobber_test_function_with_cpu_context (target_func,
        &input, &output);
    g_assert_cmpstr (fixture->result->str, ==, "><");
    assert_cpu_contexts_are_equal (&input, &output);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (cpu_flag_clobber)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    gsize flags_input, flags_output;

    interceptor_fixture_attach (fixture, 0, target_func, '>', '<');

    invoke_clobber_test_function_with_carry_set (target_func,
        &flags_input, &flags_output);
    g_assert_cmpstr (fixture->result->str, ==, "><");
    g_assert_cmphex (flags_output, ==, flags_input);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (i_can_has_attachability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (interceptor_fixture_try_attach (fixture, 0,
        func->code + func->code_offset, '>', '<'),
        ==, GUM_ATTACH_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

#ifdef HAVE_I386

TESTCASE (already_attached)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_function, GUM_INVOCATION_LISTENER (
          fixture->listener_context[0]->listener),
      NULL), ==, GUM_ATTACH_ALREADY_ATTACHED);
}

TESTCASE (relative_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_relative_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (absolute_indirect_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_absolute_indirect_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (two_indirects_to_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_two_jumps_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (relocation_of_early_call)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_early_call_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach (fixture, 0);

  proxy_func_free (proxy_func);
}

# if GLIB_SIZEOF_VOID_P == 8

TESTCASE (relocation_of_early_rip_relative_call)
{
  ProxyFunc proxy_func;

  proxy_func =
      proxy_func_new_early_rip_relative_call_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach (fixture, 0);

  proxy_func_free (proxy_func);
}

# endif

#endif /* HAVE_I386 */

#ifndef HAVE_ASAN

TESTCASE (replace_one)
{
  gpointer (* malloc_impl) (gsize size);
  guint counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc, &counter, NULL), ==, GUM_REPLACE_OK);
  ret = malloc_impl (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert().  We do the real assert after reverting, as failing
   * asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  g_assert_cmpint (counter, ==, 1);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), ==, 0x42);

  ret = malloc_impl (1);
  g_assert_cmpint (counter, ==, 1);
  free (ret);
}

#ifdef HAVE_FRIDA_GLIB

static gpointer replacement_malloc_calling_malloc_and_replaced_free (
    gsize size);
static void replacement_free_doing_nothing (gpointer mem);

TESTCASE (replace_two)
{
  gpointer malloc_impl, free_impl;
  guint malloc_counter = 0, free_counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();
  free_impl = interceptor_fixture_get_libc_free ();

  gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc_calling_malloc_and_replaced_free, &malloc_counter,
      NULL);
  gum_interceptor_replace (fixture->interceptor, free_impl,
      replacement_free_doing_nothing, &free_counter, NULL);

  ret = malloc (0x42);
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  gum_interceptor_revert (fixture->interceptor, free_impl);
  g_assert_cmpint (malloc_counter, ==, 1);
  g_assert_cmpint (free_counter, ==, 1);

  free (ret);
}

static gpointer
replacement_malloc_calling_malloc_and_replaced_free (gsize size)
{
  GumInvocationContext * ctx;
  guint * counter;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);
  (*counter)++;

  result = malloc (1);
  free (result); /* should do nothing because we replace free */

#if defined (__GNUC__) && __GNUC__ >= 12
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wuse-after-free"
#endif
  return result;
#if defined (__GNUC__) && __GNUC__ >= 12
# pragma GCC diagnostic pop
#endif
}

static void
replacement_free_doing_nothing (gpointer mem)
{
  GumInvocationContext * ctx;
  guint * counter;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);
  (*counter)++;
}

#endif
#endif

TESTCASE (replace_then_attach)
{
  guint target_counter = 0;

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
      target_function, replacement_target_function, &target_counter, NULL),
      ==, GUM_REPLACE_OK);
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">/|\\<");
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (replace_keep_original)
{
  gpointer (* malloc_impl) (gsize size);
  gpointer (* original_impl) (gsize size) = NULL;
  guint counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc, &counter, (void **) &original_impl),
      ==, GUM_REPLACE_OK);
  g_assert_nonnull (original_impl);
  ret = original_impl (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert().  We do the real assert after reverting, as failing
   * asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  g_assert_cmpint (counter, ==, 0);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), !=, 0x42);

  free (ret);
}

static gpointer
replacement_target_function (GString * str)
{
  gpointer result;

  g_string_append_c (str, '/');
  result = target_function (str);
  g_string_append_c (str, '\\');

  return result;
}

TESTCASE (i_can_has_replaceability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        func->code + func->code_offset, replacement_malloc, NULL, NULL),
        ==, GUM_REPLACE_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

TESTCASE (already_replaced)
{
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, malloc, NULL, NULL), ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, malloc, NULL, NULL), ==, GUM_REPLACE_ALREADY_REPLACED);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

#ifdef HAVE_WINDOWS

static gpointer
hit_target_function_repeatedly (gpointer data)
{
  volatile guint * n_passes = (guint *) data;
  GString * str;

  str = g_string_new ("");

  do
  {
    target_function (NULL);
  }
  while (*n_passes != 0);

  g_string_free (str, TRUE);

  return NULL;
}

#endif

typedef gpointer (* MallocFunc) (gsize size);

static gpointer
replacement_malloc (gsize size)
{
  GumInvocationContext * ctx;
  MallocFunc malloc_impl;
  guint * counter;
  gpointer a;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  malloc_impl = (MallocFunc) ctx->function;
  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);

  (*counter)++;

  a = malloc_impl (1);
  free (a);

  /* equivalent to the above */
  a = malloc (1);
  free (a);

  g_assert_cmpuint ((gsize) gum_invocation_context_get_nth_argument (ctx, 0),
      ==, size);

  return GSIZE_TO_POINTER (size);
}

TESTCASE (replace_then_replace_fast)
{
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function, NULL, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (attach_then_replace_fast)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
        target_function, GUM_INVOCATION_LISTENER (listener), NULL),
      ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_detach (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_object_unref (listener);
}

TESTCASE (replace_fast_then_replace)
{
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function, NULL, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (replace_fast_then_attach)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);

  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
        target_function, GUM_INVOCATION_LISTENER (listener), NULL),
      ==, GUM_ATTACH_WRONG_TYPE);

  gum_interceptor_revert (fixture->interceptor, target_function);
  g_object_unref (listener);
}

TESTCASE (replace_fast_then_replace_fast)
{
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_ALREADY_REPLACED);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (i_can_has_replaceability_fast)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i != count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
          func->code + func->code_offset, replacement_malloc, NULL),
        ==, GUM_REPLACE_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

TESTCASE (replace_one_fast)
{
  gpointer result;

  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function_fast,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);

  result = target_function (fixture->result);

  gum_interceptor_revert (fixture->interceptor, target_function);
  g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "/|\\");

  g_string_free (fixture->result, TRUE);
  fixture->result = g_string_sized_new (4096);

  result = target_function (fixture->result);
  g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "|");
}

static gpointer
replacement_target_function_fast (GString * str)
{
  gpointer result;

  g_string_append_c (str, '/');
  result = target_function_fast (str);
  g_string_append_c (str, '\\');

  return result;
}

TESTCASE (fast_interceptor_performance)
{
  GTimer * timer;
  gpointer result;
  gdouble duration_default, duration_fast;

  timer = g_timer_new ();

  /* Normal Interceptor */
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function_fast, NULL,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);
  g_timer_reset (timer);

  for (gsize i = 0; i != 1000000; i++)
  {
    g_string_truncate (fixture->result, 0);
    result = target_function (fixture->result);
    g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "/|\\");
  }
  duration_default = g_timer_elapsed (timer, NULL);
  gum_interceptor_revert (fixture->interceptor, target_function);

  /* Fast Interceptor */
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function_fast,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);
  g_timer_reset (timer);
  for (gsize i = 0; i != 1000000; i++)
  {
    g_string_truncate (fixture->result, 0);
    result = target_function (fixture->result);
    g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "/|\\");
  }
  duration_fast = g_timer_elapsed (timer, NULL);
  gum_interceptor_revert (fixture->interceptor, target_function);

  g_timer_destroy (timer);

  g_print ("<duration_fast=%f duration_default=%f ratio=%f> ",
      duration_fast, duration_default, duration_fast / duration_default);
}
