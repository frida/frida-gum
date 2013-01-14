/*
 * Copyright (C) 2008-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "testutil.h"

#ifndef G_OS_WIN32
#include <dlfcn.h>
#endif

#define PROCESS_TESTCASE(NAME) \
    void test_process_ ## NAME (void)
#define PROCESS_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Process", test_process, NAME)

TEST_LIST_BEGIN (process)
  PROCESS_TESTENTRY (process_threads)
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
#endif
TEST_LIST_END ()

typedef struct _TestForEachContext {
  gboolean value_to_return;
  guint number_of_calls;
} TestForEachContext;

#ifdef HAVE_DARWIN
static gboolean store_export_address_if_malloc (const gchar * name,
    GumAddress address, gpointer user_data);
#endif

static gboolean thread_found_cb (GumThreadDetails * details,
    gpointer user_data);
static gboolean module_found_cb (const gchar * name, GumAddress address,
    const gchar * path, gpointer user_data);
static gboolean export_found_cb (const gchar * name, GumAddress address,
    gpointer user_data);
static gboolean range_found_cb (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

PROCESS_TESTCASE (process_threads)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
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
store_export_address_if_malloc (const gchar * name,
                                GumAddress address,
                                gpointer user_data)
{
  if (strcmp (name, "malloc") == 0)
  {
    *((GumAddress *) user_data) = address;
    return FALSE;
  }

  return TRUE;
}

#endif

static gboolean
thread_found_cb (GumThreadDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
module_found_cb (const gchar * name,
                 GumAddress address,
                 const gchar * path,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
export_found_cb (const gchar * name,
                 GumAddress address,
                 gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
range_found_cb (const GumMemoryRange * range,
                GumPageProtection prot,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}
