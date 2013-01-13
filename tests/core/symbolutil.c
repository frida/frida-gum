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

#define SYMUTIL_TESTCASE(NAME) \
    void test_symbolutil_ ## NAME (void)
#define SYMUTIL_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/SymbolUtil", test_symbolutil, NAME)

TEST_LIST_BEGIN (symbolutil)
#ifdef HAVE_SYMBOL_BACKEND
  SYMUTIL_TESTENTRY (symbol_details_from_address)
  SYMUTIL_TESTENTRY (symbol_name_from_address)
  SYMUTIL_TESTENTRY (find_external_public_function)
  SYMUTIL_TESTENTRY (find_local_static_function)
  SYMUTIL_TESTENTRY (find_functions_named)
  SYMUTIL_TESTENTRY (find_functions_matching)
#endif
TEST_LIST_END ()

#ifdef HAVE_SYMBOL_BACKEND

static void GUM_CDECL gum_dummy_function_0 (void);
static void GUM_STDCALL gum_dummy_function_1 (void);

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
