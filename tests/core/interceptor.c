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
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  INTERCEPTOR_TESTENTRY (attach_to_heap_api)
#endif
#ifdef HAVE_DARWIN
  INTERCEPTOR_TESTENTRY (attach_to_darwin_apis)
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
  INTERCEPTOR_TESTENTRY (replace_function)
  INTERCEPTOR_TESTENTRY (two_replaced_functions)
  INTERCEPTOR_TESTENTRY (replace_function_then_attach_to_it)
#endif
TEST_LIST_END ()

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

INTERCEPTOR_TESTCASE (attach_to_heap_api)
{
  volatile gpointer p;

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

#ifdef HAVE_DARWIN

#include "backend-darwin/gumdarwin.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <unistd.h>

static gpointer perform_read (gpointer data);

INTERCEPTOR_TESTCASE (attach_to_darwin_apis)
{
  int ret;

  {
    int * (* error_impl) (void);

    error_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "__error"));

    interceptor_fixture_attach_listener (fixture, 0, error_impl, '>', '<');

    errno = ECONNREFUSED;
    ret = *(error_impl ());
    g_assert_cmpint (ret, ==, ECONNREFUSED);
    g_assert_cmpstr (fixture->result->str, ==, "><><");

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }

  {
    int (* strcmp_impl) (const char * s1, const char * s2);

    strcmp_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "strcmp"));

    interceptor_fixture_attach_listener (fixture, 0, strcmp_impl, '>', '<');

    g_assert_cmpint (strcmp_impl ("badger", "badger"), ==, 0);

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }

#ifndef HAVE_ARM
  {
    char * (* strrchr_impl) (const char * s, int c);
    const char * s = "badger";

    strrchr_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "strrchr"));

    interceptor_fixture_attach_listener (fixture, 0, strrchr_impl, '>', '<');

    g_assert (strrchr_impl (s, 'd') == s + 2);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }
#endif

  {
    ssize_t (* read_impl) (int fd, void * buf, size_t n);
    int fds[2];
    GThread * read_thread;
    guint8 value = 42;

    read_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "read"));

    ret = pipe (fds);
    g_assert (ret == 0);

    read_thread =
        g_thread_new ("perform-read", perform_read, GSIZE_TO_POINTER (fds[0]));
    g_usleep (G_USEC_PER_SEC / 10);
    interceptor_fixture_attach_listener (fixture, 0, read_impl, '>', '<');
    write (fds[1], &value, sizeof (value));
    g_thread_join (read_thread);
    g_assert_cmpstr (fixture->result->str, ==, "");

    close (fds[0]);

    value = 0;
    ret = read_impl (fds[0], &value, sizeof (value));
    g_assert_cmpint (ret, ==, -1);
    g_assert_cmpuint (value, ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    close (fds[1]);

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }

  {
    int server, client;
    int (* accept_impl) (int socket, struct sockaddr * address,
        socklen_t * address_len);
    struct sockaddr_in addr = { 0, };
    socklen_t addr_len;

    server = socket (AF_INET, SOCK_STREAM, 0);
    g_assert (server != -1);

    addr.sin_family = AF_INET;
    addr.sin_port = g_random_int_range (1337, 31337);
    addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind (server, (struct sockaddr *) &addr, sizeof (addr));
    g_assert (ret == 0);

    ret = listen (server, 1);
    g_assert (ret == 0);

    client = socket (AF_INET, SOCK_STREAM, 0);
    g_assert (client != -1);
    ret = fcntl (client, F_SETFL, O_NONBLOCK);
    g_assert (ret == 0);
    ret = connect (client, (struct sockaddr *) &addr, sizeof (addr));
    g_assert (ret == -1 && errno == EINPROGRESS);

    accept_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "accept"));

    interceptor_fixture_attach_listener (fixture, 0, accept_impl, '>', '<');

    addr_len = sizeof (addr);
    ret = accept_impl (server, (struct sockaddr *) &addr, &addr_len);
    g_assert (ret >= 0);

    close (ret);
    close (client);
    close (server);

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }

  {
    int (* posix_spawnattr_setbinpref_np_impl) (posix_spawnattr_t * attr,
        size_t count, cpu_type_t * pref, size_t * ocount);
    posix_spawnattr_t attr;
    cpu_type_t pref;
    size_t ocount;

    posix_spawnattr_setbinpref_np_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib",
        "posix_spawnattr_setbinpref_np"));

    interceptor_fixture_attach_listener (fixture, 0,
        posix_spawnattr_setbinpref_np_impl, '>', '<');

    posix_spawnattr_init (&attr);
    pref = CPU_TYPE_ARM64;
    ret = posix_spawnattr_setbinpref_np_impl (&attr, 1, &pref, &ocount);
    g_assert_cmpint (ret, ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "><");
    posix_spawnattr_destroy (&attr);

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }

  {
    mach_port_t self;
    int * (* pid_for_task_impl) (void);
    int pid = 0;

    self = mach_task_self ();

    pid_for_task_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "pid_for_task"));

    interceptor_fixture_attach_listener (fixture, 0, pid_for_task_impl,
        '>', '<');

    ret = pid_for_task (self, &pid);
    g_assert_cmpint (ret, ==, KERN_SUCCESS);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);

    g_assert_cmpint (pid, ==, getpid ());
  }

#ifndef HAVE_ARM
  {
    mach_port_t (* mach_host_self_impl) (void);
    mach_port_t host;

    mach_host_self_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "mach_host_self"));

    interceptor_fixture_attach_listener (fixture, 0, mach_host_self_impl,
        '>', '<');

    host = mach_host_self_impl ();
    g_assert_cmpint (host, !=, 0);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);

    g_assert_cmpint (host, ==, mach_host_self_impl ());
  }

  {
    gpointer (* xpc_dictionary_create_impl) (const gchar * const * keys,
        gconstpointer * values, gsize count);
    gpointer (* xpc_retain_impl) (gpointer object);
    void (* xpc_release_impl) (gpointer object);
    gpointer dict;

    xpc_dictionary_create_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib",
        "xpc_dictionary_create"));
    xpc_retain_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "xpc_retain"));
    xpc_release_impl = GSIZE_TO_POINTER (
        gum_module_find_export_by_name ("libSystem.B.dylib", "xpc_release"));

    dict = xpc_dictionary_create_impl (NULL, NULL, 0);

    xpc_retain_impl (dict);

    interceptor_fixture_attach_listener (fixture, 0, xpc_retain_impl, '>', '<');

    xpc_retain_impl (dict);
    g_assert_cmpstr (fixture->result->str, ==, "><");

    xpc_release_impl (dict);
    xpc_release_impl (dict);
    xpc_release_impl (dict);

    interceptor_fixture_detach_listener (fixture, 0);
    g_string_truncate (fixture->result, 0);
  }
#endif
}

static gpointer
perform_read (gpointer data)
{
  gint fd = GPOINTER_TO_SIZE (data);
  guint8 value = 0;
  int ret;

  ret = read (fd, &value, sizeof (value));
  g_assert_cmpint (ret, ==, 1);
  g_assert_cmpuint (value, ==, 42);

  return NULL;
}

#endif

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

INTERCEPTOR_TESTCASE (replace_function)
{
  gpointer (* malloc_impl) (gsize size);
  guint counter = 0;
  volatile gpointer ret;

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

INTERCEPTOR_TESTCASE (two_replaced_functions)
{
  guint malloc_counter = 0, free_counter = 0;
  volatile gpointer ret;

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

