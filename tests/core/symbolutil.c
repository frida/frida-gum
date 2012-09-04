/*
 * Copyright (C) 2008-2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#define SYMUTIL_TESTCASE(NAME) \
    void test_symbolutil_ ## NAME (void)
#define SYMUTIL_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/SymbolUtil", test_symbolutil, NAME)

TEST_LIST_BEGIN (symbolutil)
  SYMUTIL_TESTENTRY (process_modules)
  SYMUTIL_TESTENTRY (process_ranges)
  SYMUTIL_TESTENTRY (module_exports)
  SYMUTIL_TESTENTRY (module_ranges_can_be_enumerated)
#ifndef HAVE_LINUX
  SYMUTIL_TESTENTRY (module_base)
  SYMUTIL_TESTENTRY (module_export_can_be_found)
  SYMUTIL_TESTENTRY (module_export_matches_system_lookup)
#endif
#ifdef HAVE_DARWIN
  SYMUTIL_TESTENTRY (darwin_enumerate_modules)
  SYMUTIL_TESTENTRY (darwin_enumerate_ranges)
  SYMUTIL_TESTENTRY (darwin_module_exports)
#endif
#ifdef HAVE_SYMBOL_BACKEND
  SYMUTIL_TESTENTRY (symbol_details_from_address)
  SYMUTIL_TESTENTRY (symbol_name_from_address)
  SYMUTIL_TESTENTRY (find_external_public_function)
  SYMUTIL_TESTENTRY (find_local_static_function)
  SYMUTIL_TESTENTRY (find_functions_named)
  SYMUTIL_TESTENTRY (find_functions_matching)
#endif
TEST_LIST_END ()

typedef struct _TestForEachContext {
  gboolean value_to_return;
  guint number_of_calls;
} TestForEachContext;

static gboolean module_found_cb (const gchar * name, GumAddress address,
    const gchar * path, gpointer user_data);
static gboolean export_found_cb (const gchar * name, GumAddress address,
    gpointer user_data);
static gboolean range_found_cb (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

#ifdef HAVE_SYMBOL_BACKEND
static void GUM_CDECL gum_dummy_function_0 (void);
static void GUM_STDCALL gum_dummy_function_1 (void);
#endif

SYMUTIL_TESTCASE (process_modules)
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

SYMUTIL_TESTCASE (process_ranges)
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

SYMUTIL_TESTCASE (module_exports)
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

SYMUTIL_TESTCASE (module_ranges_can_be_enumerated)
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

#ifndef HAVE_LINUX

SYMUTIL_TESTCASE (module_base)
{
  g_assert (gum_module_find_base_address (SYSTEM_MODULE_NAME) != 0);
}

SYMUTIL_TESTCASE (module_export_can_be_found)
{
  g_assert (gum_module_find_export_by_name (SYSTEM_MODULE_NAME,
      SYSTEM_MODULE_EXPORT) != 0);
}

SYMUTIL_TESTCASE (module_export_matches_system_lookup)
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

SYMUTIL_TESTCASE (darwin_enumerate_modules)
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

SYMUTIL_TESTCASE (darwin_enumerate_ranges)
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

SYMUTIL_TESTCASE (darwin_module_exports)
{
  mach_port_t task = gum_test_get_target_task ();
  TestForEachContext ctx;

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
}

#endif

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

#ifdef HAVE_SYMBOL_BACKEND

SYMUTIL_TESTCASE (symbol_details_from_address)
{
  GumSymbolDetails details;

  g_assert (gum_symbol_details_from_address (gum_dummy_function_0, &details));

  g_assert_cmphex (GPOINTER_TO_SIZE (details.address), ==,
      GPOINTER_TO_SIZE (gum_dummy_function_0));
  g_assert (g_str_has_prefix (details.module_name, "gum-tests"));
  g_assert_cmpstr (details.symbol_name, ==, "gum_dummy_function_0");
  assert_basename_equals (__FILE__, details.file_name);
  g_assert_cmpuint (details.line_number, >, 0);
}

SYMUTIL_TESTCASE (symbol_name_from_address)
{
  gchar * symbol_name;

  symbol_name = gum_symbol_name_from_address (gum_dummy_function_1);
  g_assert_cmpstr (symbol_name, ==, "gum_dummy_function_1");
  g_free (symbol_name);
}

SYMUTIL_TESTCASE (find_external_public_function)
{
  g_assert (gum_find_function ("g_object_new") != NULL);
}

SYMUTIL_TESTCASE (find_local_static_function)
{
  gpointer function_address;

  function_address = gum_find_function ("gum_dummy_function_0");
  g_assert_cmphex (GPOINTER_TO_SIZE (function_address), ==,
      GPOINTER_TO_SIZE (gum_dummy_function_0));
}

SYMUTIL_TESTCASE (find_functions_named)
{
  GArray * functions;

  functions = gum_find_functions_named ("g_object_new");
  g_assert_cmpuint (functions->len, >=, 1);
  g_array_free (functions, TRUE);
}

SYMUTIL_TESTCASE (find_functions_matching)
{
  GArray * functions;
  gpointer a, b;

  functions = gum_find_functions_matching ("gum_dummy_function_*");
  g_assert_cmpuint (functions->len, ==, 2);

  a = g_array_index (functions, gpointer, 0);
  b = g_array_index (functions, gpointer, 1);
  if (a != GUM_FUNCPTR_TO_POINTER (gum_dummy_function_0))
  {
    gpointer hold = a;

    a = b;
    b = hold;
  }

  g_assert_cmphex (GPOINTER_TO_SIZE (a),
      ==, GPOINTER_TO_SIZE (gum_dummy_function_0));
  g_assert_cmphex (GPOINTER_TO_SIZE (b),
      ==, GPOINTER_TO_SIZE (gum_dummy_function_1));

  g_array_free (functions, TRUE);
}

static void GUM_CDECL
gum_dummy_function_0 (void)
{
  g_print ("%s\n", G_STRFUNC);
}

static void GUM_STDCALL
gum_dummy_function_1 (void)
{
  g_print ("%s\n", G_STRFUNC);
}

#endif

