/*
 * Copyright (C) 2008-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "valgrind.h"

#ifndef G_OS_WIN32
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include <stdlib.h>
#include <string.h>

#define PROCESS_TESTCASE(NAME) \
    void test_process_ ## NAME (void)
#define PROCESS_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Process", test_process, NAME)

TEST_LIST_BEGIN (process)
#ifndef HAVE_MIPS
  PROCESS_TESTENTRY (process_threads)
#endif
  PROCESS_TESTENTRY (process_modules)
  PROCESS_TESTENTRY (process_ranges)
  PROCESS_TESTENTRY (module_imports)
  PROCESS_TESTENTRY (module_exports)
  PROCESS_TESTENTRY (module_ranges_can_be_enumerated)
  PROCESS_TESTENTRY (module_base)
  PROCESS_TESTENTRY (module_export_can_be_found)
  PROCESS_TESTENTRY (module_export_matches_system_lookup)
#ifdef G_OS_WIN32
  PROCESS_TESTENTRY (get_set_system_error)
  PROCESS_TESTENTRY (get_current_thread_id)
#endif
#ifdef HAVE_DARWIN
  PROCESS_TESTENTRY (darwin_enumerate_modules)
  PROCESS_TESTENTRY (darwin_enumerate_ranges)
  PROCESS_TESTENTRY (darwin_module_exports)
  PROCESS_TESTENTRY (process_malloc_ranges)
#endif
TEST_LIST_END ()

typedef struct _TestForEachContext {
  gboolean value_to_return;
  guint number_of_calls;
} TestForEachContext;

typedef struct _TestRangeContext {
  GumMemoryRange range;
  gboolean found;
  gboolean found_exact;
} TestRangeContext;

#ifndef G_OS_WIN32
static gboolean store_export_address_if_tricky_module_export (
    const GumExportDetails * details, gpointer user_data);
#endif

#ifdef HAVE_DARWIN
static gboolean store_export_address_if_mach_msg (
    const GumExportDetails * details, gpointer user_data);
#endif

static gpointer sleeping_dummy (gpointer data);
static gboolean thread_found_cb (const GumThreadDetails * details,
    gpointer user_data);
static gboolean module_found_cb (const GumModuleDetails * details,
    gpointer user_data);
static gboolean import_found_cb (const GumImportDetails * details,
    gpointer user_data);
static gboolean export_found_cb (const GumExportDetails * details,
    gpointer user_data);
static gboolean range_found_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean range_check_cb (const GumRangeDetails * details,
    gpointer user_data);
#ifdef HAVE_DARWIN
static gboolean malloc_range_found_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
static gboolean malloc_range_check_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
#endif

PROCESS_TESTCASE (process_threads)
{
  gboolean done = FALSE;
  GThread * thread_a, * thread_b;
  TestForEachContext ctx;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  thread_a = g_thread_new ("process-test-sleeping-dummy-a", sleeping_dummy,
      &done);
  thread_b = g_thread_new ("process-test-sleeping-dummy-b", sleeping_dummy,
      &done);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >=, 2);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  done = TRUE;
  g_thread_join (thread_b);
  g_thread_join (thread_a);
}

PROCESS_TESTCASE (process_modules)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

PROCESS_TESTCASE (process_ranges)
{
  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    const gsize stack_buf_size = 50;
    guint8 * stack_buf;

    malloc_buf = malloc (malloc_buf_size);
    stack_buf = g_alloca (stack_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert (ctx.found);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf) + 1;
    ctx.range.size = malloc_buf_size - 1;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert (ctx.found);

    free (malloc_buf);

    ctx.range.base_address = GUM_ADDRESS (stack_buf);
    ctx.range.size = stack_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert (ctx.found);
  }
}

#ifdef HAVE_DARWIN

PROCESS_TESTCASE (process_malloc_ranges)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    const gsize stack_buf_size = 50;
    guint8 stack_buf[stack_buf_size];

    malloc_buf = malloc (malloc_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert (ctx.found);
    g_assert (ctx.found_exact);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf) + 1;
    ctx.range.size = malloc_buf_size - 1;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert (ctx.found);
    g_assert (!ctx.found_exact);

    free (malloc_buf);

    ctx.range.base_address = GUM_ADDRESS (stack_buf);
    ctx.range.size = stack_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert (!ctx.found);
    g_assert (!ctx.found_exact);
  }
}

#endif

PROCESS_TESTCASE (module_imports)
{
#ifndef HAVE_QNX
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_imports (GUM_TESTS_MODULE_NAME, import_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_imports (GUM_TESTS_MODULE_NAME, import_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
#else
  (void) import_found_cb;
#endif
}

PROCESS_TESTCASE (module_exports)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_exports (SYSTEM_MODULE_NAME, export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_exports (SYSTEM_MODULE_NAME, export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

PROCESS_TESTCASE (module_ranges_can_be_enumerated)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_ranges (SYSTEM_MODULE_NAME, GUM_PAGE_READ,
      range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_ranges (SYSTEM_MODULE_NAME, GUM_PAGE_READ,
      range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

PROCESS_TESTCASE (module_base)
{
  g_assert (gum_module_find_base_address (SYSTEM_MODULE_NAME) != 0);
}

PROCESS_TESTCASE (module_export_can_be_found)
{
  g_assert (gum_module_find_export_by_name (SYSTEM_MODULE_NAME,
      SYSTEM_MODULE_EXPORT) != 0);
}

PROCESS_TESTCASE (module_export_matches_system_lookup)
{
#ifndef G_OS_WIN32
  void * lib, * system_address;
  GumAddress enumerate_address, find_by_name_address;

  lib = dlopen (TRICKY_MODULE_NAME, RTLD_NOW | RTLD_GLOBAL);
  g_assert (lib != NULL);
  system_address = dlsym (lib, TRICKY_MODULE_EXPORT);

  enumerate_address = 0;
  gum_module_enumerate_exports (TRICKY_MODULE_NAME,
      store_export_address_if_tricky_module_export, &enumerate_address);
  g_assert (enumerate_address != 0);

  find_by_name_address =
      gum_module_find_export_by_name (TRICKY_MODULE_NAME, TRICKY_MODULE_EXPORT);

  g_assert_cmphex (enumerate_address, ==, GPOINTER_TO_SIZE (system_address));
  g_assert_cmphex (find_by_name_address, ==, GPOINTER_TO_SIZE (system_address));

  dlclose (lib);
#endif
}

#ifndef G_OS_WIN32
static gboolean
store_export_address_if_tricky_module_export (const GumExportDetails * details,
                                              gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION
      && strcmp (details->name, TRICKY_MODULE_EXPORT) == 0)
  {
    *((GumAddress *) user_data) = details->address;
    return FALSE;
  }

  return TRUE;
}
#endif

#ifdef G_OS_WIN32
PROCESS_TESTCASE (get_current_thread_id)
{
  g_assert_cmphex (gum_process_get_current_thread_id (), ==,
      GetCurrentThreadId ());
}

PROCESS_TESTCASE (get_set_system_error)
{
  gum_thread_set_system_error (0x12345678);
  g_assert_cmpint (GetLastError (), ==, 0x12345678);
  SetLastError (0x89ABCDEF);
  g_assert_cmpint (gum_thread_get_system_error (), ==, (gint) 0x89ABCDEF);
}
#endif

#ifdef HAVE_DARWIN

#include <gum/backend-darwin/gumdarwin.h>
#include <mach/mach.h>

static mach_port_t
gum_test_get_target_task (void)
{
#if 1
  return mach_task_self ();
#else
  mach_port_t task;
  kern_return_t ret;

  ret = task_for_pid (mach_task_self (), 12304, &task);
  g_assert_cmpint (ret, ==, 0);

  return task;
#endif
}

PROCESS_TESTCASE (darwin_enumerate_modules)
{
  mach_port_t task = gum_test_get_target_task ();
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_modules (task, module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_modules (task, module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

PROCESS_TESTCASE (darwin_enumerate_ranges)
{
  mach_port_t task = gum_test_get_target_task ();
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX, range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX, range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

PROCESS_TESTCASE (darwin_module_exports)
{
  mach_port_t task = gum_test_get_target_task ();
  TestForEachContext ctx;
  GumAddress actual_mach_msg_address = 0;
  GumAddress expected_mach_msg_address;
  void * module;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      store_export_address_if_mach_msg, &actual_mach_msg_address);
  g_assert (actual_mach_msg_address != 0);

  module = dlopen (SYSTEM_MODULE_NAME, 0);
  expected_mach_msg_address = GUM_ADDRESS (dlsym (module, "mach_msg"));
  g_assert (expected_mach_msg_address != 0);
  dlclose (module);

  g_assert_cmphex (actual_mach_msg_address, ==, expected_mach_msg_address);
}

static gboolean
store_export_address_if_mach_msg (const GumExportDetails * details,
                                  gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION
      && strcmp (details->name, "mach_msg") == 0)
  {
    *((GumAddress *) user_data) = details->address;
    return FALSE;
  }

  return TRUE;
}

#endif

static gpointer
sleeping_dummy (gpointer data)
{
  volatile gboolean * done = (gboolean *) data;

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

static gboolean
thread_found_cb (const GumThreadDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
module_found_cb (const GumModuleDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
import_found_cb (const GumImportDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  if (strcmp (details->name, "malloc") == 0)
    g_assert_cmpint (details->type, ==, GUM_IMPORT_FUNCTION);

  return ctx->value_to_return;
}

static gboolean
export_found_cb (const GumExportDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

#ifdef HAVE_DARWIN
  if (strcmp (details->name, "malloc") == 0)
    g_assert_cmpint (details->type, ==, GUM_EXPORT_FUNCTION);
  else if (g_str_has_prefix (details->name, "OBJC_CLASS_"))
    g_assert_cmpint (details->type, ==, GUM_EXPORT_VARIABLE);
  else if (strcmp (details->name, "dispatch_async_f") == 0)
    g_assert_cmpint (details->type, ==, GUM_EXPORT_FUNCTION);
#endif

  return ctx->value_to_return;
}

static gboolean
range_found_cb (const GumRangeDetails * details,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
range_check_cb (const GumRangeDetails * details,
                gpointer user_data)
{
  TestRangeContext * ctx = (TestRangeContext *) user_data;
  GumAddress ctx_start, ctx_end;
  GumAddress details_start, details_end;

  ctx_start = ctx->range.base_address;
  ctx_end = ctx_start + ctx->range.size;

  details_start = details->range->base_address;
  details_end = details_start + details->range->size;

  if (ctx_start == details_start && ctx_end == details_end)
  {
    ctx->found_exact = TRUE;
  }

  if (ctx_start >= details_start && ctx_end <= details_end)
  {
    ctx->found = TRUE;
  }

  return TRUE;
}

#ifdef HAVE_DARWIN

static gboolean
malloc_range_found_cb (const GumMallocRangeDetails * details,
                       gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
malloc_range_check_cb (const GumMallocRangeDetails * details,
                       gpointer user_data)
{
  TestRangeContext * ctx = (TestRangeContext *) user_data;
  GumAddress ctx_start, ctx_end;
  GumAddress details_start, details_end;

  ctx_start = ctx->range.base_address;
  ctx_end = ctx_start + ctx->range.size;

  details_start = details->range->base_address;
  details_end = details_start + details->range->size;

  /* malloc may allocate a larger memory block than requested */
  if (ctx_start == details_start && ctx_end <= details_end)
  {
    ctx->found_exact = TRUE;
  }

  if (ctx_start >= details_start && ctx_end <= details_end)
  {
    ctx->found = TRUE;
  }

  return TRUE;
}

#endif
