/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumfunctionparser.h"

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define FUNCPARSER_TESTCASE(NAME) \
    void test_functionparser_ ## NAME (void)
#define FUNCPARSER_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE (FunctionParser, test_functionparser, NAME)

static int GUM_STDCALL sample_func (int a, int b, int c);

TEST_LIST_BEGIN (functionparser)
  FUNCPARSER_TESTENTRY (ret_size)
  /*
#ifdef G_OS_WIN32
  FUNCPARSER_TESTENTRY (ret_torture)
#endif
  */
TEST_LIST_END ()

FUNCPARSER_TESTCASE (ret_size)
{
  GumFunctionParser fp;
  GumFunctionDetails details;

  gum_function_parser_init (&fp);
  gum_function_parser_parse (&fp, sample_func, &details);

#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmpint (details.num_arguments, ==, 3);
#else
  g_assert_cmpint (details.num_arguments, ==, 0);
#endif
}

#ifdef G_OS_WIN32

static void
parse_exported_function (const gchar * name,
                         gpointer address,
                         gpointer user_data)
{
  GumFunctionParser fp;
  GumFunctionDetails details;

  /*g_print ("%s: ", name);*/
  gum_function_parser_init (&fp);
  gum_function_parser_parse (&fp, address, &details);
  /*g_print ("%d\n", details.arglist_size);*/

  g_assert_cmpint (details.num_arguments, <=, 32);
}

/*
FUNCPARSER_TESTCASE (ret_torture)
{
  HMODULE mod;
  const gchar * module_name = "opengl32.dll";

  mod = LoadLibraryA (module_name);

  gum_module_enumerate_exports (module_name, parse_exported_function, NULL);

  FreeLibrary (mod);
}
*/

#endif

static int GUM_STDCALL
sample_func (int a, int b, int c)
{
  if (a)
  {
    return b + c;
  }
  else
  {
    return b - c;
  }
}

