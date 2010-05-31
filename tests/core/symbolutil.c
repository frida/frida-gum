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

#ifdef G_OS_WIN32
#define SYSTEM_MODULE_NAME "kernel32.dll"
#else
#define SYSTEM_MODULE_NAME "libc.so.6"
#endif

static void export_found_cb (const gchar * name, gpointer address,
    gpointer user_data);

#ifndef GUM_DISABLE_SYMBOL_UTIL
static void GUM_CDECL dummy_function_0 (void);
static void GUM_STDCALL dummy_function_1 (void);
#endif

TEST_LIST_BEGIN (symbolutil)
  TEST_ENTRY_SIMPLE (SymbolUtil, test_module_exports)
#ifndef GUM_DISABLE_SYMBOL_UTIL
  TEST_ENTRY_SIMPLE (SymbolUtil, test_symbol_details_from_address)
  TEST_ENTRY_SIMPLE (SymbolUtil, test_symbol_name_from_address)
  TEST_ENTRY_SIMPLE (SymbolUtil, test_find_external_public_function)
  TEST_ENTRY_SIMPLE (SymbolUtil, test_find_local_static_function)
  TEST_ENTRY_SIMPLE (SymbolUtil, test_find_functions_matching)
#endif
TEST_LIST_END ()

static void
test_module_exports (void)
{
  guint count = 0;

  gum_module_enumerate_exports (SYSTEM_MODULE_NAME, export_found_cb, &count);

  g_assert_cmpuint (count, >, 0);
}

static void
export_found_cb (const gchar * name,
                 gpointer address,
                 gpointer user_data)
{
  guint * count = user_data;
  (*count) ++;
}

#ifndef GUM_DISABLE_SYMBOL_UTIL

static void
test_symbol_details_from_address (void)
{
  GumSymbolDetails details;

  g_assert (gum_symbol_details_from_address (dummy_function_0, &details));

  g_assert_cmphex (GPOINTER_TO_SIZE (details.address), ==,
      GPOINTER_TO_SIZE (dummy_function_0));
  g_assert (g_str_has_prefix (details.module_name, "gumtest"));
  g_assert_cmpstr (details.symbol_name, ==, "dummy_function_0");
  assert_basename_equals (__FILE__, details.file_name);
  g_assert_cmpuint (details.line_number, >, 0);
}

static void
test_symbol_name_from_address (void)
{
  gchar * symbol_name;

  symbol_name = gum_symbol_name_from_address (dummy_function_1);
  g_assert_cmpstr (symbol_name, ==, "dummy_function_1");
  g_free (symbol_name);
}

static void
test_find_external_public_function (void)
{
  g_assert (gum_find_function ("g_hash_table_new") != NULL);
}

static void
test_find_local_static_function (void)
{
  gpointer function_address;

  function_address = gum_find_function ("dummy_function_0");
  g_assert_cmphex (GPOINTER_TO_SIZE (function_address), ==,
      GPOINTER_TO_SIZE (dummy_function_0));
}

static void
test_find_functions_matching (void)
{
  GArray * functions;

  functions = gum_find_functions_matching ("dummy_function_*");
  g_assert_cmpuint (functions->len, ==, 2);
  g_assert_cmphex (GPOINTER_TO_SIZE (g_array_index (functions, gpointer, 0)),
      ==, GPOINTER_TO_SIZE (dummy_function_0));
  g_assert_cmphex (GPOINTER_TO_SIZE (g_array_index (functions, gpointer, 1)),
      ==, GPOINTER_TO_SIZE (dummy_function_1));
  g_array_free (functions, TRUE);
}

static void GUM_CDECL
dummy_function_0 (void)
{
  g_print ("%s\n", G_STRFUNC);
}

static void GUM_STDCALL
dummy_function_1 (void)
{
  g_print ("%s\n", G_STRFUNC);
}

#endif /* GUM_DISABLE_SYMBOL_UTIL */
