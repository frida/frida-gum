/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gummapper.h"

#include "testutil.h"
#include "gum/gumnativemoduleresolver.h"
#include "gum/gumnativeprocessmemory.h"

#include <windows.h>

#define TESTCASE(NAME) \
    void test_pe_mapper_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/PeMapper", test_pe_mapper, NAME)

TESTLIST_BEGIN (pe_mapper)
  TESTENTRY (exports_can_be_resolved_and_called)
  TESTENTRY (constructor_runs_dll_main)
  TESTENTRY (imports_are_resolved)
  TESTENTRY (destructor_runs_dll_main)
  TESTENTRY (tls_storage_is_per_thread)
  TESTENTRY (tls_storage_for_multiple_modules)
  TESTENTRY (maps_into_another_process)
  TESTENTRY (maps_tls_into_another_process)
TESTLIST_END ()

typedef struct _GumTestPeTarget GumTestPeTarget;
typedef struct _GumTlsThreadContext GumTlsThreadContext;
typedef struct _GumMultiTlsContext GumMultiTlsContext;

struct _GumTestPeTarget
{
  GumNativeModuleResolver * resolver;
  GumMapper * mapper;
  gpointer base;
  gsize size;

  void (* constructor) (void);
  void (* destructor) (void);
};

struct _GumTlsThreadContext
{
  int (* get) (void);
  void (* set) (int value);
  int observed_initial;
};

struct _GumMultiTlsContext
{
  int (* get_a) (void);
  int (* get_b) (void);
  int observed_a;
  int observed_b;
};

static void gum_test_pe_target_open (GumTestPeTarget * target);
static void gum_test_pe_target_open_path (GumTestPeTarget * target,
    const gchar * path);
static void gum_test_pe_target_close (GumTestPeTarget * target);
static gpointer gum_test_pe_tls_thread (gpointer data);
static gpointer gum_test_pe_multi_tls_thread (gpointer data);

TESTCASE (exports_can_be_resolved_and_called)
{
  GumTestPeTarget target;
  int (* sum) (int a, int b);

  gum_test_pe_target_open (&target);

  sum = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_sum"));
  g_assert_nonnull (sum);
  g_assert_cmpint (sum (3, 4), ==, 7);

  gum_test_pe_target_close (&target);
}

TESTCASE (constructor_runs_dll_main)
{
  GumTestPeTarget target;
  int (* get_magic) (void);

  gum_test_pe_target_open (&target);

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_get_magic"));
  g_assert_nonnull (get_magic);
  g_assert_cmphex (get_magic (), ==, 0x1337);

  gum_test_pe_target_close (&target);
}

TESTCASE (imports_are_resolved)
{
  GumTestPeTarget target;
  unsigned int (* get_pid) (void);

  gum_test_pe_target_open (&target);

  get_pid = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_get_pid"));
  g_assert_nonnull (get_pid);
  g_assert_cmpuint (get_pid (), ==, GetCurrentProcessId ());

  gum_test_pe_target_close (&target);
}

TESTCASE (destructor_runs_dll_main)
{
  GumTestPeTarget target;
  int (* get_magic) (void);

  gum_test_pe_target_open (&target);

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_get_magic"));
  g_assert_cmpint (get_magic (), ==, 0x1337);

  target.destructor ();
  g_assert_cmpint (get_magic (), ==, 0);

  gum_memory_free (target.base, target.size);
  g_object_unref (target.mapper);
  g_object_unref (target.resolver);
}

TESTCASE (tls_storage_is_per_thread)
{
  GumTestPeTarget target;
  GumTlsThreadContext ctx;
  GThread * thread;

  gum_test_pe_target_open_path (&target, GUM_TESTS_PEMAPPER_TLS_TARGET);

  ctx.get = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_tls_get"));
  ctx.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_pe_tls_set"));
  g_assert_nonnull (ctx.get);
  g_assert_nonnull (ctx.set);

  g_assert_cmphex (ctx.get (), ==, 0x1234);
  ctx.set (0xaaaa);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  ctx.observed_initial = 0;
  thread = g_thread_new ("tls-probe", gum_test_pe_tls_thread, &ctx);
  g_thread_join (thread);

  g_assert_cmphex (ctx.observed_initial, ==, 0x1234);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  gum_test_pe_target_close (&target);
}

TESTCASE (tls_storage_for_multiple_modules)
{
  GumTestPeTarget a, b;
  GumMultiTlsContext multi;
  GThread * thread;
  GumTlsThreadContext solo;

  gum_test_pe_target_open_path (&a, GUM_TESTS_PEMAPPER_TLS_TARGET);
  gum_test_pe_target_open_path (&b, GUM_TESTS_PEMAPPER_TLS_TARGET);

  multi.get_a = GSIZE_TO_POINTER (
      gum_mapper_resolve (a.mapper, "gum_test_pe_tls_get"));
  multi.get_b = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_pe_tls_get"));
  g_assert_nonnull (multi.get_a);
  g_assert_nonnull (multi.get_b);

  g_assert_cmphex (multi.get_a (), ==, 0x1234);
  g_assert_cmphex (multi.get_b (), ==, 0x1234);

  multi.observed_a = 0;
  multi.observed_b = 0;
  thread = g_thread_new ("tls-multi", gum_test_pe_multi_tls_thread, &multi);
  g_thread_join (thread);
  g_assert_cmphex (multi.observed_a, ==, 0x1234);
  g_assert_cmphex (multi.observed_b, ==, 0x1234);

  gum_test_pe_target_close (&a);

  solo.get = multi.get_b;
  solo.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_pe_tls_set"));
  solo.observed_initial = 0;
  thread = g_thread_new ("tls-solo", gum_test_pe_tls_thread, &solo);
  g_thread_join (thread);
  g_assert_cmphex (solo.observed_initial, ==, 0x1234);

  gum_test_pe_target_close (&b);
}

TESTCASE (maps_into_another_process)
{
  STARTUPINFOA si = { 0, };
  PROCESS_INFORMATION pi = { 0, };
  GumNativeModuleResolver * resolver;
  gchar * contents;
  gsize length;
  GBytes * blob;
  GError * error = NULL;
  GumMapper * mapper;
  GumProcessMemory * target;
  gsize size;
  gpointer base;
  GumAddress ctor, get_magic;
  HANDLE thread;
  DWORD magic = 0;

  si.cb = sizeof (si);
  if (!CreateProcessA (GUM_TESTS_PEMAPPER_VICTIM, NULL, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
  {
    g_print ("<skipping, unable to spawn victim> ");
    return;
  }

  {
    gchar name[64];
    HANDLE ready;

    g_snprintf (name, sizeof (name), "frida-pemapper-victim-%lu",
        (gulong) pi.dwProcessId);
    ready = CreateEventA (NULL, TRUE, FALSE, name);
    WaitForSingleObject (ready, INFINITE);
    CloseHandle (ready);
  }

  resolver = gum_native_module_resolver_new ();

  g_assert_true (g_file_get_contents (GUM_TESTS_PEMAPPER_TARGET, &contents,
      &length, NULL));
  blob = g_bytes_new_take (contents, length);

  mapper = gum_mapper_new_take_blob ("module.dll", blob,
      GUM_MODULE_RESOLVER (resolver), &error);
  g_assert_no_error (error);

  target = GUM_PROCESS_MEMORY (
      gum_native_process_memory_new_remote (pi.dwProcessId, pi.hProcess));
  gum_mapper_set_target (mapper, target);

  size = gum_mapper_size (mapper);
  base = VirtualAllocEx (pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  g_assert_nonnull (base);

  gum_mapper_map (mapper, GUM_ADDRESS (base), &error);
  g_assert_no_error (error);

  ctor = gum_mapper_constructor (mapper);
  thread = CreateRemoteThread (pi.hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE) GSIZE_TO_POINTER (ctor), NULL, 0, NULL);
  g_assert_nonnull (thread);
  WaitForSingleObject (thread, INFINITE);
  CloseHandle (thread);

  get_magic = gum_mapper_resolve (mapper, "gum_test_pe_get_magic");
  g_assert_cmphex (get_magic, !=, 0);
  thread = CreateRemoteThread (pi.hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE) GSIZE_TO_POINTER (get_magic), NULL, 0, NULL);
  g_assert_nonnull (thread);
  WaitForSingleObject (thread, INFINITE);
  GetExitCodeThread (thread, &magic);
  CloseHandle (thread);

  g_assert_cmphex (magic, ==, 0x1337);

  TerminateProcess (pi.hProcess, 0);
  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  g_object_unref (mapper);
  g_object_unref (target);
  g_object_unref (resolver);
}

TESTCASE (maps_tls_into_another_process)
{
  STARTUPINFOA si = { 0, };
  PROCESS_INFORMATION pi = { 0, };
  GumNativeModuleResolver * resolver;
  gchar * contents;
  gsize length;
  GBytes * blob;
  GError * error = NULL;
  GumMapper * mapper;
  GumProcessMemory * target;
  gsize size;
  gpointer base;
  GumAddress ctor, tls_get;
  HANDLE thread;
  DWORD value = 0;

  si.cb = sizeof (si);
  if (!CreateProcessA (GUM_TESTS_PEMAPPER_VICTIM, NULL, NULL, NULL, FALSE,
      CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
  {
    g_print ("<skipping, unable to spawn victim> ");
    return;
  }

  {
    gchar name[64];
    HANDLE ready;

    g_snprintf (name, sizeof (name), "frida-pemapper-victim-%lu",
        (gulong) pi.dwProcessId);
    ready = CreateEventA (NULL, TRUE, FALSE, name);
    WaitForSingleObject (ready, INFINITE);
    CloseHandle (ready);
  }

  resolver = gum_native_module_resolver_new ();

  g_assert_true (g_file_get_contents (GUM_TESTS_PEMAPPER_TLS_TARGET, &contents,
      &length, NULL));
  blob = g_bytes_new_take (contents, length);

  mapper = gum_mapper_new_take_blob ("module.dll", blob,
      GUM_MODULE_RESOLVER (resolver), &error);
  g_assert_no_error (error);

  target = GUM_PROCESS_MEMORY (
      gum_native_process_memory_new_remote (pi.dwProcessId, pi.hProcess));
  gum_mapper_set_target (mapper, target);

  size = gum_mapper_size (mapper);
  base = VirtualAllocEx (pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  g_assert_nonnull (base);

  gum_mapper_map (mapper, GUM_ADDRESS (base), &error);
  g_assert_no_error (error);

  ctor = gum_mapper_constructor (mapper);
  thread = CreateRemoteThread (pi.hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE) GSIZE_TO_POINTER (ctor), NULL, 0, NULL);
  g_assert_nonnull (thread);
  WaitForSingleObject (thread, INFINITE);
  CloseHandle (thread);

  tls_get = gum_mapper_resolve (mapper, "gum_test_pe_tls_get");
  g_assert_cmphex (tls_get, !=, 0);
  thread = CreateRemoteThread (pi.hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE) GSIZE_TO_POINTER (tls_get), NULL, 0, NULL);
  g_assert_nonnull (thread);
  WaitForSingleObject (thread, INFINITE);
  GetExitCodeThread (thread, &value);
  CloseHandle (thread);

  g_assert_cmphex (value, ==, 0x1234);

  TerminateProcess (pi.hProcess, 0);
  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  g_object_unref (mapper);
  g_object_unref (target);
  g_object_unref (resolver);
}

static void
gum_test_pe_target_open (GumTestPeTarget * target)
{
  gum_test_pe_target_open_path (target, GUM_TESTS_PEMAPPER_TARGET);
}

static void
gum_test_pe_target_open_path (GumTestPeTarget * target,
                              const gchar * path)
{
  gchar * contents;
  gsize length;
  GBytes * blob;
  GError * error = NULL;

  target->resolver = gum_native_module_resolver_new ();

  g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
  blob = g_bytes_new_take (contents, length);

  target->mapper = gum_mapper_new_take_blob ("module.dll", blob,
      GUM_MODULE_RESOLVER (target->resolver), &error);
  g_assert_no_error (error);
  g_assert_nonnull (target->mapper);

  target->size = gum_mapper_size (target->mapper);
  target->base = gum_memory_allocate (NULL, target->size,
      gum_query_page_size (), GUM_PAGE_RW);

  gum_mapper_map (target->mapper, GUM_ADDRESS (target->base), &error);
  g_assert_no_error (error);

  target->constructor =
      GSIZE_TO_POINTER (gum_mapper_constructor (target->mapper));
  target->destructor =
      GSIZE_TO_POINTER (gum_mapper_destructor (target->mapper));

  target->constructor ();
}

static void
gum_test_pe_target_close (GumTestPeTarget * target)
{
  target->destructor ();

  g_object_unref (target->mapper);
  gum_memory_free (target->base, target->size);
  g_object_unref (target->resolver);
}

static gpointer
gum_test_pe_tls_thread (gpointer data)
{
  GumTlsThreadContext * ctx = data;

  ctx->observed_initial = ctx->get ();
  ctx->set (0xbbbb);

  return NULL;
}

static gpointer
gum_test_pe_multi_tls_thread (gpointer data)
{
  GumMultiTlsContext * ctx = data;

  ctx->observed_a = ctx->get_a ();
  ctx->observed_b = ctx->get_b ();

  return NULL;
}
