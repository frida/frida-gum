/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-fixture.c"

TEST_LIST_BEGIN (interceptor)
#ifdef HAVE_I386
  INTERCEPTOR_TESTENTRY (cpu_register_clobber)
  INTERCEPTOR_TESTENTRY (cpu_flag_clobber)
#endif

  INTERCEPTOR_TESTENTRY (i_can_has_attachability)
#ifdef HAVE_I386
  INTERCEPTOR_TESTENTRY (already_attached)
  INTERCEPTOR_TESTENTRY (relative_proxy_function)
  INTERCEPTOR_TESTENTRY (absolute_indirect_proxy_function)
  INTERCEPTOR_TESTENTRY (two_indirects_to_function)
  INTERCEPTOR_TESTENTRY (relocation_of_early_call)
#endif

  INTERCEPTOR_TESTENTRY (attach_one)
  INTERCEPTOR_TESTENTRY (attach_two)
  INTERCEPTOR_TESTENTRY (attach_to_recursive_function)
  INTERCEPTOR_TESTENTRY (attach_to_special_function)
#if !defined (HAVE_IOS) && defined (HAVE_ARM)
  INTERCEPTOR_TESTENTRY (attach_to_unaligned_function)
#endif
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  INTERCEPTOR_TESTENTRY (attach_to_heap_api)
#endif
#ifdef HAVE_ANDROID
  INTERCEPTOR_TESTENTRY (attach_to_android_apis)
#endif
  INTERCEPTOR_TESTENTRY (attach_to_own_api)
#ifdef G_OS_WIN32
  INTERCEPTOR_TESTENTRY (attach_detach_torture)
#endif
  INTERCEPTOR_TESTENTRY (thread_id)
#if !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  INTERCEPTOR_TESTENTRY (intercepted_free_in_thread_exit)
#endif
  INTERCEPTOR_TESTENTRY (function_arguments)
  INTERCEPTOR_TESTENTRY (function_return_value)
#ifdef HAVE_I386
  INTERCEPTOR_TESTENTRY (function_cpu_context_on_enter)
#endif
  INTERCEPTOR_TESTENTRY (ignore_current_thread)
  INTERCEPTOR_TESTENTRY (ignore_current_thread_nested)
  INTERCEPTOR_TESTENTRY (ignore_other_threads)
  INTERCEPTOR_TESTENTRY (detach)
  INTERCEPTOR_TESTENTRY (listener_ref_count)
  INTERCEPTOR_TESTENTRY (function_data)

#if !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  INTERCEPTOR_TESTENTRY (i_can_has_replaceability)
  INTERCEPTOR_TESTENTRY (already_replaced)
# ifndef HAVE_ASAN
  INTERCEPTOR_TESTENTRY (replace_function)
  INTERCEPTOR_TESTENTRY (two_replaced_functions)
# endif
  INTERCEPTOR_TESTENTRY (replace_function_then_attach_to_it)
#endif

#ifdef HAVE_QNX
  INTERCEPTOR_TESTENTRY (intercept_malloc_and_create_thread)
#endif
TEST_LIST_END ()

#ifdef HAVE_QNX
static gpointer thread_doing_nothing (gpointer data);
static gpointer thread_calling_pthread_setspecific (gpointer data);
#endif
#ifdef G_OS_WIN32
static gpointer hit_target_function_repeatedly (gpointer data);
#endif
static gpointer replacement_malloc (gsize size);
static gpointer replacement_target_function (GString * str);

INTERCEPTOR_TESTCASE (attach_one)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

INTERCEPTOR_TESTCASE (attach_two)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach_listener (fixture, 1, target_function, 'c', 'd');
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

INTERCEPTOR_TESTCASE (attach_to_recursive_function)
{
  interceptor_fixture_attach_listener (fixture, 0, recursive_function,
      '>', '<');
  recursive_function (fixture->result, 4);
  g_assert_cmpstr (fixture->result->str, ==, ">>>>>0<1<2<3<4<");
}

INTERCEPTOR_TESTCASE (attach_to_special_function)
{
  interceptor_fixture_attach_listener (fixture, 0, special_function, '>', '<');
  special_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

#if !defined (HAVE_IOS) && defined (HAVE_ARM)

/*
 * XXX: Although this problem also applies to iOS we don't want to run this
 *      test there until we have an easy JIT API for hiding the annoying
 *      details necessary to deal with code-signing.
 */

#include "gumthumbwriter.h"

INTERCEPTOR_TESTCASE (attach_to_unaligned_function)
{
  gpointer page, code;
  GumThumbWriter tw;
  gint (* f) (void);

  page = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  code = page + 2;

  /* Aligned on a 2 byte boundary and minimum 8 bytes long */
  gum_thumb_writer_init (&tw, code);
  gum_thumb_writer_put_push_regs (&tw, 8,
      ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);
  gum_thumb_writer_put_push_regs (&tw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);
  gum_thumb_writer_put_pop_regs (&tw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);
  gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 1337);
  gum_thumb_writer_put_pop_regs (&tw, 8,
      ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);
  gum_thumb_writer_free (&tw);

  f = code + 1;

  interceptor_fixture_attach_listener (fixture, 0, f, '>', '<');
  g_assert_cmpint (f (), ==, 1337);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  g_string_truncate (fixture->result, 0);
  interceptor_fixture_detach_listener (fixture, 0);
  g_assert_cmpint (f (), ==, 1337);
  g_assert_cmpstr (fixture->result->str, ==, "");

  gum_free_pages (page);
}

#endif

INTERCEPTOR_TESTCASE (attach_to_heap_api)
{
  volatile gpointer p;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  interceptor_fixture_attach_listener (fixture, 0, malloc, '>', '<');
  interceptor_fixture_attach_listener (fixture, 1, free, 'a', 'b');
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  p = malloc (1);
  free (p);
  g_assert_cmpstr (fixture->result->str, ==, "><ab");

  interceptor_fixture_detach_listener (fixture, 0);
  interceptor_fixture_detach_listener (fixture, 1);

  g_assert_cmpstr (fixture->result->str, ==, "><ab");
}

#ifdef HAVE_ANDROID

INTERCEPTOR_TESTCASE (attach_to_android_apis)
{
  {
    pid_t (* fork_impl) (void);
    pid_t pid;

    fork_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libc.so", "fork"));

    interceptor_fixture_attach_listener (fixture, 0, fork_impl, '>', '<');

    pid = fork_impl ();
    if (pid == 0)
    {
      exit (0);
    }
    g_assert_cmpint (pid, !=, -1);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }
}

#endif

INTERCEPTOR_TESTCASE (attach_to_own_api)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  gum_interceptor_attach_listener (fixture->interceptor, target_function,
      GUM_INVOCATION_LISTENER (listener), NULL);
  target_function (fixture->result);
  gum_interceptor_detach_listener (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_assert_cmpstr (fixture->result->str, ==, "|||");

  g_object_unref (listener);
}

#ifdef G_OS_WIN32

INTERCEPTOR_TESTCASE (attach_detach_torture)
{
  GThread * th;
  volatile guint n_passes = 100;

  th = g_thread_new ("interceptor-test-torture",
      hit_target_function_repeatedly, (gpointer) &n_passes);

  g_thread_yield ();

  do
  {
    TestCallbackListener * listener;

    interceptor_fixture_attach_listener (fixture, 0, target_function,
        'a', 'b');

    listener = test_callback_listener_new ();

    gum_interceptor_attach_listener (fixture->interceptor, target_function,
        GUM_INVOCATION_LISTENER (listener), NULL);
    gum_interceptor_detach_listener (fixture->interceptor,
        GUM_INVOCATION_LISTENER (listener));
    interceptor_fixture_detach_listener (fixture, 0);

    g_object_unref (listener);
  }
  while (--n_passes != 0);

  g_thread_join (th);
}

#endif

INTERCEPTOR_TESTCASE (thread_id)
{
  GumThreadId first_thread_id, second_thread_id;

  interceptor_fixture_attach_listener (fixture, 0, target_function, 'a', 'b');

  target_function (fixture->result);
  first_thread_id = fixture->listener_context[0]->last_thread_id;

  g_thread_join (g_thread_new ("interceptor-test-thread-id",
      (GThreadFunc) target_function, fixture->result));
  second_thread_id = fixture->listener_context[0]->last_thread_id;

  g_assert_cmpuint (second_thread_id, !=, first_thread_id);
}

INTERCEPTOR_TESTCASE (intercepted_free_in_thread_exit)
{
  interceptor_fixture_attach_listener (fixture, 0, free, 'a', 'b');
  g_thread_join (g_thread_new ("interceptor-test-thread-exit",
      target_nop_function_a, NULL));
}

INTERCEPTOR_TESTCASE (function_arguments)
{
  interceptor_fixture_attach_listener (fixture, 0, target_nop_function_a, 'a',
      'b');
  target_nop_function_a (GSIZE_TO_POINTER (0x12349876));
  g_assert_cmphex (fixture->listener_context[0]->last_seen_argument,
      ==, 0x12349876);
}

INTERCEPTOR_TESTCASE (function_return_value)
{
  gpointer return_value;

  interceptor_fixture_attach_listener (fixture, 0, target_nop_function_a, 'a',
      'b');
  return_value = target_nop_function_a (NULL);
  g_assert_cmphex (
      GPOINTER_TO_SIZE (fixture->listener_context[0]->last_return_value),
      ==, GPOINTER_TO_SIZE (return_value));
}

#ifdef HAVE_I386

INTERCEPTOR_TESTCASE (function_cpu_context_on_enter)
{
  GumCpuContext input, output;

  interceptor_fixture_attach_listener (fixture, 0, clobber_test_function, 'a',
      'b');

  fill_cpu_context_with_magic_values (&input);
  invoke_clobber_test_function_with_cpu_context (&input, &output);
  g_assert_cmpstr (fixture->result->str, ==, "ab");
  assert_cpu_contexts_are_equal (&input,
      &fixture->listener_context[0]->last_on_enter_cpu_context);
}

#endif

INTERCEPTOR_TESTCASE (ignore_current_thread)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>',
      '<');

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

INTERCEPTOR_TESTCASE (ignore_current_thread_nested)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>',
      '<');

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");
  gum_interceptor_unignore_current_thread (fixture->interceptor);
}

INTERCEPTOR_TESTCASE (ignore_other_threads)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>', '<');

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

INTERCEPTOR_TESTCASE (detach)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach_listener (fixture, 1, target_function, 'c', 'd');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");

  interceptor_fixture_detach_listener (fixture, 0);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "c|d");
}

INTERCEPTOR_TESTCASE (listener_ref_count)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, 'a', 'b');
  g_assert_cmpuint (G_OBJECT (fixture->listener_context[0])->ref_count, ==, 1);
}

#include "interceptor-functiondatalistener.c"

INTERCEPTOR_TESTCASE (function_data)
{
  TestFunctionDataListener * fd_listener;
  GumInvocationListener * listener;
  gpointer a_data = "a", b_data = "b";

  fd_listener = (TestFunctionDataListener *)
      g_object_new (TEST_TYPE_FUNCTION_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (fd_listener);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      target_nop_function_a, listener, a_data), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      target_nop_function_b, listener, b_data), ==, GUM_ATTACH_OK);

  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 0);

  target_nop_function_a ("badger");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert (fd_listener->last_on_leave_data.function_data == a_data);
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
  g_assert (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert (fd_listener->last_on_leave_data.function_data == a_data);
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
  g_assert (fd_listener->last_on_enter_data.function_data == b_data);
  g_assert (fd_listener->last_on_leave_data.function_data == b_data);
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
  g_assert (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "bdgr");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "bdgr");

  gum_interceptor_detach_listener (fixture->interceptor, listener);
  g_object_unref (fd_listener);
}

#ifdef HAVE_I386

INTERCEPTOR_TESTCASE (cpu_register_clobber)
{
  GumCpuContext input, output;

  interceptor_fixture_attach_listener (fixture, 0, clobber_test_function,
      '>', '<');

  fill_cpu_context_with_magic_values (&input);
  invoke_clobber_test_function_with_cpu_context (&input, &output);
  g_assert_cmpstr (fixture->result->str, ==, "><");
  assert_cpu_contexts_are_equal (&input, &output);
}

INTERCEPTOR_TESTCASE (cpu_flag_clobber)
{
  gsize flags_input, flags_output;

  interceptor_fixture_attach_listener (fixture, 0, clobber_test_function,
      '>', '<');

  invoke_clobber_test_function_with_carry_set (&flags_input, &flags_output);
  g_assert_cmpstr (fixture->result->str, ==, "><");
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
        func->code + func->code_offset, '>', '<'),
        ==, GUM_ATTACH_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

#ifdef HAVE_I386

INTERCEPTOR_TESTCASE (already_attached)
{
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>', '<');
  g_assert_cmpint (gum_interceptor_attach_listener (fixture->interceptor,
      target_function, GUM_INVOCATION_LISTENER (fixture->listener_context[0]),
      NULL), ==, GUM_ATTACH_ALREADY_ATTACHED);
}

INTERCEPTOR_TESTCASE (relative_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_relative_with_target (target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

INTERCEPTOR_TESTCASE (absolute_indirect_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_absolute_indirect_with_target (target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

INTERCEPTOR_TESTCASE (two_indirects_to_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_two_jumps_with_target (target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

INTERCEPTOR_TESTCASE (relocation_of_early_call)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_early_call_with_target (target_function);

  interceptor_fixture_attach_listener (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach_listener (fixture, 0);

  proxy_func_free (proxy_func);
}

#endif /* HAVE_I386 */

#ifndef HAVE_ASAN

INTERCEPTOR_TESTCASE (replace_function)
{
  gpointer (* malloc_impl) (gsize size);
  guint counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

#ifdef HAVE_LINUX
  /*
   * Get the address of malloc dynamically, as GCC is too smart about
   * malloc() and assumes the last part of this function is unreachable.
   */
  void * libc = dlopen (test_util_get_system_module_name (),
      RTLD_LAZY | RTLD_GLOBAL);
  malloc_impl = dlsym (libc, "malloc");
  dlclose (libc);
#else
  malloc_impl = malloc;
#endif

  g_assert_cmpint (gum_interceptor_replace_function (fixture->interceptor,
      malloc_impl, replacement_malloc, &counter), ==, GUM_REPLACE_OK);
  ret = malloc_impl (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert_function().  We do the real assert after reverting,
   * as failing asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert (ret != NULL);

  gum_interceptor_revert_function (fixture->interceptor, malloc_impl);
  g_assert_cmpint (counter, ==, 1);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), ==, 0x42);

  ret = malloc_impl (1);
  g_assert_cmpint (counter, ==, 1);
  free (ret);
}

static gpointer replacement_malloc_calling_malloc_and_replaced_free (
    gsize size);
static void replacement_free_doing_nothing (gpointer mem);

INTERCEPTOR_TESTCASE (two_replaced_functions)
{
  guint malloc_counter = 0, free_counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  gum_interceptor_replace_function (fixture->interceptor,
      malloc, replacement_malloc_calling_malloc_and_replaced_free,
      &malloc_counter);
  gum_interceptor_replace_function (fixture->interceptor,
      free, replacement_free_doing_nothing, &free_counter);

  ret = malloc (0x42);
  g_assert (ret != NULL);

  gum_interceptor_revert_function (fixture->interceptor, malloc);
  gum_interceptor_revert_function (fixture->interceptor, free);
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
  g_assert (ctx != NULL);

  counter = (guint *)
      gum_invocation_context_get_replacement_function_data (ctx);
  (*counter)++;

  result = malloc (1);
  free (result); /* should do nothing because we replace free */

  return result;
}

static void
replacement_free_doing_nothing (gpointer mem)
{
  GumInvocationContext * ctx;
  guint * counter;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  counter = (guint *)
      gum_invocation_context_get_replacement_function_data (ctx);
  (*counter)++;
}

#endif

INTERCEPTOR_TESTCASE (replace_function_then_attach_to_it)
{
  guint target_counter = 0;

  g_assert_cmpint (gum_interceptor_replace_function (fixture->interceptor,
      target_function, replacement_target_function, &target_counter),
      ==, GUM_REPLACE_OK);
  interceptor_fixture_attach_listener (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">/|\\<");
  gum_interceptor_revert_function (fixture->interceptor, target_function);
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

INTERCEPTOR_TESTCASE (i_can_has_replaceability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (gum_interceptor_replace_function (fixture->interceptor,
        func->code + func->code_offset, replacement_malloc, NULL),
        ==, GUM_REPLACE_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

INTERCEPTOR_TESTCASE (already_replaced)
{
  g_assert_cmpint (gum_interceptor_replace_function (fixture->interceptor,
        target_function, malloc, NULL), ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace_function (fixture->interceptor,
        target_function, malloc, NULL), ==, GUM_REPLACE_ALREADY_REPLACED);
  gum_interceptor_revert_function (fixture->interceptor, target_function);
}

#ifdef HAVE_QNX

INTERCEPTOR_TESTCASE (intercept_malloc_and_create_thread)
{
  pthread_key_t key;
  pthread_t thread1, thread2;

  interceptor_fixture_attach_listener (fixture, 0, malloc, 'a', 'b');

  g_assert (pthread_key_create (&key, NULL) == 0);

  pthread_create (&thread1, NULL, thread_doing_nothing, NULL);
  /* The target thread MUST be the highest number thread to date in the
   * process, in order to avoid using the cached keydata in
   * pthread_setspecific.
   */
  pthread_create (&thread2, NULL, thread_calling_pthread_setspecific,
      (void *) key);

  pthread_join (thread2, NULL);
  pthread_join (thread1, NULL);

  g_assert_cmpstr (fixture->result->str, ==, "ab");
}

static gpointer
thread_doing_nothing (gpointer data)
{
  sleep (1);
  return NULL;
}

static gpointer
thread_calling_pthread_setspecific (gpointer data)
{
  volatile pthread_key_t key = (pthread_key_t) data;

  g_assert_cmpint (pthread_setspecific (key, GSIZE_TO_POINTER (0xaaaaaaaa)),
      ==, 0);

  return NULL;
}

#endif

#ifdef G_OS_WIN32

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
  g_assert (ctx != NULL);

  malloc_impl = (MallocFunc) ctx->function;
  counter = (guint *)
      gum_invocation_context_get_replacement_function_data (ctx);

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
