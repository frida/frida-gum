/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-darwin-fixture.c"

#include "backend-darwin/gumdarwin.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <unistd.h>

TESTLIST_BEGIN (interceptor_darwin)
  TESTENTRY (can_attach_to_errno)
  TESTENTRY (can_attach_to_strcmp)
  TESTENTRY (can_attach_to_strrchr)
  TESTENTRY (can_attach_to_read)
  TESTENTRY (can_attach_to_accept)
  TESTENTRY (can_attach_to_posix_spawnattr_setbinpref_np)
  TESTENTRY (can_attach_to_pid_for_task)
  TESTENTRY (can_attach_to_mach_host_self)
  TESTENTRY (can_attach_to_xpc_retain)
  TESTENTRY (can_attach_to_sqlite3_close)
  TESTENTRY (can_attach_to_sqlite3_thread_cleanup)

  TESTENTRY (attach_performance)
  TESTENTRY (replace_performance)

#ifdef HAVE_IOS
  TESTENTRY (should_retain_code_signing_status)
  TESTENTRY (cydia_substrate_replace_performance)
#endif
TESTLIST_END ()

typedef struct _TestPerformanceContext TestPerformanceContext;

struct _TestPerformanceContext
{
  GumInterceptor * interceptor;
  GumInvocationListener * listener;

  void (* MSHookFunction) (void * symbol, void * replace, void ** result);

  guint count;
};

static gpointer perform_read (gpointer data);

static gboolean attach_if_function_export (const GumExportDetails * details,
    gpointer user_data);
static gboolean replace_if_function_export (const GumExportDetails * details,
    gpointer user_data);

static void dummy_replacement_never_called (void);

TESTCASE (can_attach_to_errno)
{
  int * (* error_impl) (void);
  int ret;

  error_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "__error"));

  interceptor_fixture_attach_listener (fixture, 0, error_impl, '>', '<');

  errno = ECONNREFUSED;
  ret = *(error_impl ());
  g_assert_cmpint (ret, ==, ECONNREFUSED);
  g_assert_cmpstr (fixture->result->str, ==, "><><");
}

TESTCASE (can_attach_to_strcmp)
{
  int (* strcmp_impl) (const char * s1, const char * s2);

  strcmp_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "strcmp"));

  interceptor_fixture_attach_listener (fixture, 0, strcmp_impl, '>', '<');

  g_assert_cmpint (strcmp_impl ("badger", "badger"), ==, 0);
}

TESTCASE (can_attach_to_strrchr)
{
  char * (* strrchr_impl) (const char * s, int c);
  const char * s = "badger";

  strrchr_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "strrchr"));

  interceptor_fixture_attach_listener (fixture, 0, strrchr_impl, '>', '<');

  g_assert_true (strrchr_impl (s, 'd') == s + 2);
  g_assert_cmpstr (fixture->result->str, ==, "><");
}

TESTCASE (can_attach_to_read)
{
  ssize_t (* read_impl) (int fd, void * buf, size_t n);
  int ret, fds[2];
  GThread * read_thread;
  guint8 value = 42;

  read_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "read"));

  ret = pipe (fds);
  g_assert_cmpint (ret, ==, 0);

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
}

TESTCASE (can_attach_to_accept)
{
  int server, client, ret;
  int (* accept_impl) (int socket, struct sockaddr * address,
      socklen_t * address_len);
  struct sockaddr_in addr = { 0, };
  socklen_t addr_len;

  server = socket (AF_INET, SOCK_STREAM, 0);
  g_assert_cmpint (server, !=, -1);

  addr.sin_family = AF_INET;
  addr.sin_port = g_random_int_range (1337, 31337);
  addr.sin_addr.s_addr = INADDR_ANY;
  ret = bind (server, (struct sockaddr *) &addr, sizeof (addr));
  g_assert_cmpint (ret, ==, 0);

  ret = listen (server, 1);
  g_assert_cmpint (ret, ==, 0);

  client = socket (AF_INET, SOCK_STREAM, 0);
  g_assert_cmpint (client, !=, -1);
  ret = fcntl (client, F_SETFL, O_NONBLOCK);
  g_assert_cmpint (ret, ==, 0);
  ret = connect (client, (struct sockaddr *) &addr, sizeof (addr));
  g_assert_true (ret == -1 && errno == EINPROGRESS);

  accept_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "accept"));

  interceptor_fixture_attach_listener (fixture, 0, accept_impl, '>', '<');

  addr_len = sizeof (addr);
  ret = accept_impl (server, (struct sockaddr *) &addr, &addr_len);
  g_assert_cmpint (ret, >=, 0);

  close (ret);
  close (client);
  close (server);
}

TESTCASE (can_attach_to_posix_spawnattr_setbinpref_np)
{
  int (* posix_spawnattr_setbinpref_np_impl) (posix_spawnattr_t * attr,
      size_t count, cpu_type_t * pref, size_t * ocount);
  posix_spawnattr_t attr;
  cpu_type_t pref;
  size_t ocount;
  int ret;

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
}

TESTCASE (can_attach_to_pid_for_task)
{
  mach_port_t self;
  int * (* pid_for_task_impl) (void);
  int pid = 0, ret;

  self = mach_task_self ();

  pid_for_task_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "pid_for_task"));

  interceptor_fixture_attach_listener (fixture, 0, pid_for_task_impl,
      '>', '<');

  ret = pid_for_task (self, &pid);
  g_assert_cmpint (ret, ==, KERN_SUCCESS);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  g_assert_cmpint (pid, ==, getpid ());
}

TESTCASE (can_attach_to_mach_host_self)
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

  g_assert_cmpint (host, ==, mach_host_self_impl ());
}

TESTCASE (can_attach_to_xpc_retain)
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
}

TESTCASE (can_attach_to_sqlite3_close)
{
  gint (* close_impl) (gpointer connection);

  close_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_close"));

  interceptor_fixture_attach_listener (fixture, 0, close_impl, '>', '<');

  close_impl (NULL);
  g_assert_cmpstr (fixture->result->str, ==, "><");
}

TESTCASE (can_attach_to_sqlite3_thread_cleanup)
{
#ifndef HAVE_ARM
  void (* thread_cleanup_impl) (void);

  thread_cleanup_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_thread_cleanup"));

  interceptor_fixture_attach_listener (fixture, 0, thread_cleanup_impl,
      '>', '<');

  thread_cleanup_impl ();
  g_assert_cmpstr (fixture->result->str, ==, "><");

  interceptor_fixture_detach_listener (fixture, 0);
  g_string_truncate (fixture->result, 0);
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

TESTCASE (attach_performance)
{
  gpointer sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  ctx.interceptor = fixture->interceptor;
  ctx.listener = GUM_INVOCATION_LISTENER (test_callback_listener_new ());
  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_interceptor_begin_transaction (ctx.interceptor);

  gum_module_enumerate_exports ("libsqlite3.dylib", attach_if_function_export,
      &ctx);

  gum_interceptor_end_transaction (ctx.interceptor);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);

  g_object_unref (ctx.listener);
}

TESTCASE (replace_performance)
{
  gpointer sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  ctx.interceptor = fixture->interceptor;
  ctx.listener = NULL;
  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_interceptor_begin_transaction (ctx.interceptor);

  gum_module_enumerate_exports ("libsqlite3.dylib", replace_if_function_export,
      &ctx);

  gum_interceptor_end_transaction (ctx.interceptor);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);
}

static gboolean
attach_if_function_export (const GumExportDetails * details,
                           gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    GumAttachReturn attach_ret;

    attach_ret = gum_interceptor_attach_listener (ctx->interceptor,
        GSIZE_TO_POINTER (details->address), ctx->listener, NULL);
    if (attach_ret == GUM_ATTACH_OK)
    {
      ctx->count++;
    }
    else
    {
      g_printerr ("\n\nFailed to attach to %s: %s\n", details->name,
          (attach_ret == GUM_ATTACH_WRONG_SIGNATURE)
              ? "wrong signature"
              : "already attached");
    }
  }

  return TRUE;
}

static gboolean
replace_if_function_export (const GumExportDetails * details,
                            gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    GumReplaceReturn replace_ret;

    replace_ret = gum_interceptor_replace_function (ctx->interceptor,
        GSIZE_TO_POINTER (details->address), dummy_replacement_never_called,
        NULL);
    if (replace_ret == GUM_REPLACE_OK)
    {
      ctx->count++;
    }
    else
    {
      g_printerr ("\n\nFailed to replace %s: %s\n", details->name,
          (replace_ret == GUM_REPLACE_WRONG_SIGNATURE)
              ? "wrong signature"
              : "already attached");
    }
  }

  return TRUE;
}

static void
dummy_replacement_never_called (void)
{
}

#ifdef HAVE_IOS

#define CS_OPS_STATUS 0
#define CS_VALID 0x0000001

extern int csops (pid_t pid, unsigned int ops, void * useraddr,
    size_t usersize);

static gboolean replace_with_cydia_substrate_if_function_export (
    const GumExportDetails * details, gpointer user_data);

TESTCASE (should_retain_code_signing_status)
{
  gint (* close_impl) (gpointer connection);
  gint res;
  uint32_t attributes;

  if (g_file_test ("/electra", G_FILE_TEST_IS_DIR))
  {
    g_print ("<skipped on Electra> ");
    return;
  }

  close_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_close"));
  interceptor_fixture_attach_listener (fixture, 0, close_impl, '>', '<');

  g_assert_cmpstr (fixture->result->str, ==, "");
  close_impl (NULL);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  attributes = 0;
  res = csops (0, CS_OPS_STATUS, &attributes, sizeof (attributes));
  g_assert_cmpint (res, !=, -1);

  g_assert_true ((attributes & CS_VALID) != 0);
}

TESTCASE (cydia_substrate_replace_performance)
{
  gpointer cydia_substrate, sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  cydia_substrate = dlopen (
      "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
      RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (cydia_substrate);

  ctx.MSHookFunction = dlsym (cydia_substrate, "MSHookFunction");
  g_assert_nonnull (ctx.MSHookFunction);

  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_module_enumerate_exports ("libsqlite3.dylib",
      replace_with_cydia_substrate_if_function_export, &ctx);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);

  dlclose (cydia_substrate);
}

static gboolean
replace_with_cydia_substrate_if_function_export (
    const GumExportDetails * details,
    gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    void * original;

    ctx->MSHookFunction (GSIZE_TO_POINTER (details->address),
        dummy_replacement_never_called, &original);
    ctx->count++;
  }

  return TRUE;
}

#endif
