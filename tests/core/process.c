/*
 * Copyright (C) 2008-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#ifndef G_OS_WIN32
#include <dlfcn.h>
#endif
#include <stdlib.h>

#define PROCESS_TESTCASE(NAME) \
    void test_process_ ## NAME (void)
#define PROCESS_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Process", test_process, NAME)

TEST_LIST_BEGIN (process)
#ifndef HAVE_ANDROID
  PROCESS_TESTENTRY (process_threads)
#endif
  PROCESS_TESTENTRY (process_modules)
  PROCESS_TESTENTRY (process_ranges)
  PROCESS_TESTENTRY (module_exports)
  PROCESS_TESTENTRY (module_ranges_can_be_enumerated)
  PROCESS_TESTENTRY (module_base)
  PROCESS_TESTENTRY (module_export_can_be_found)
  PROCESS_TESTENTRY (module_export_matches_system_lookup)
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

#ifdef HAVE_DARWIN
static gboolean store_export_address_if_malloc (
    const GumExportDetails * details, gpointer user_data);
#endif

#ifndef HAVE_ANDROID
static gpointer sleeping_dummy (gpointer data);
static gboolean thread_found_cb (const GumThreadDetails * details,
    gpointer user_data);
#endif
static gboolean module_found_cb (const GumModuleDetails * details,
    gpointer user_data);
static gboolean export_found_cb (const GumExportDetails * details,
    gpointer user_data);
static gboolean range_found_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean range_check_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean malloc_range_found_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
static gboolean malloc_range_check_cb (
    const GumMallocRangeDetails * details, gpointer user_data);

#ifndef HAVE_ANDROID

PROCESS_TESTCASE (process_threads)
{
  TestForEachContext ctx;
  GThread * thread;
  gboolean done = FALSE;

  thread = g_thread_new ("process-test-sleeping-dummy", sleeping_dummy, &done);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  done = TRUE;
  g_thread_join (thread);
}

#endif

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
  GumAddress gum_address;
  void * lib, * system_address;

  gum_address =
      gum_module_find_export_by_name (SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);

  lib = dlopen (SYSTEM_MODULE_NAME, RTLD_NOW | RTLD_GLOBAL);
  g_assert (lib != NULL);
  system_address = dlsym (lib, SYSTEM_MODULE_EXPORT);
  dlclose (lib);

  g_assert_cmphex (gum_address, ==, GPOINTER_TO_SIZE (system_address));
#endif
}

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
  GumAddress actual_malloc_address = 0;
  GumAddress expected_malloc_address;
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
      store_export_address_if_malloc, &actual_malloc_address);
  g_assert (actual_malloc_address != 0);

  module = dlopen (SYSTEM_MODULE_NAME, 0);
  expected_malloc_address = GUM_ADDRESS (dlsym (module, "malloc"));
  g_assert (expected_malloc_address != 0);
  dlclose (module);

  g_assert_cmphex (actual_malloc_address, ==, expected_malloc_address);
}

static gboolean
store_export_address_if_malloc (const GumExportDetails * details,
                                gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION
      && strcmp (details->name, "malloc") == 0)
  {
    *((GumAddress *) user_data) = details->address;
    return FALSE;
  }

  return TRUE;
}

#endif

#ifndef HAVE_ANDROID

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

#endif

static gboolean
module_found_cb (const GumModuleDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

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
  if (g_str_has_prefix (details->name, "OBJC_CLASS_"))
    g_assert_cmpint (details->type, ==, GUM_EXPORT_VARIABLE);
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
