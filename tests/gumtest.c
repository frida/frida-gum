/*
 * Copyright (C) 2008-2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include <glib.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <conio.h>
#endif

#define GUM_TEST_DECLARE(name) void gum_test_register_##name##_tests (void)
#define GUM_TEST(name) gum_test_register_##name##_tests

typedef void (* TestRegisterFunction) (void);

/* FIXME: these should be converted to use the new test infrastructure */
GUM_TEST_DECLARE (testutil);
GUM_TEST_DECLARE (interceptor);
/*
GUM_TEST_DECLARE (allocation_tracker);
GUM_TEST_DECLARE (allocator_probe);
GUM_TEST_DECLARE (allocator_probe_cxx);
GUM_TEST_DECLARE (backtracer);
GUM_TEST_DECLARE (profiler);
GUM_TEST_DECLARE (page_pool);
GUM_TEST_DECLARE (bounds_checker);
GUM_TEST_DECLARE (instance_tracker);
GUM_TEST_DECLARE (cobject_tracker);
*/

static const TestRegisterFunction test_register_functions[] =
{
  GUM_TEST (testutil),
  GUM_TEST (interceptor),
  /*
  GUM_TEST (allocation_tracker),
  GUM_TEST (allocator_probe),
  GUM_TEST (allocator_probe_cxx),
  GUM_TEST (backtracer),
  GUM_TEST (profiler),
  GUM_TEST (page_pool),
  GUM_TEST (bounds_checker),
  GUM_TEST (instance_tracker),
  GUM_TEST (cobject_tracker)
  */
};

static guint get_number_of_tests_in_suite (GTestSuite * suite);

gint
main (gint argc, gchar * argv[])
{
  gint result;
  guint i;
  GTimer * timer;
  guint num_tests;
  gdouble t;

  g_test_init (&argc, &argv, NULL);
  gum_init ();

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4210)
#endif

  TEST_RUN_LIST (symbolutil);
  TEST_RUN_LIST (codewriter);
  TEST_RUN_LIST (functionparser);
  TEST_RUN_LIST (relocator);
  /*
  TEST_RUN_LIST (tracer);
  TEST_RUN_LIST (sampler);*/
  TEST_RUN_LIST (stalker);

#ifdef _MSC_VER
#pragma warning (pop)
#endif

  for (i = 0; i < G_N_ELEMENTS (test_register_functions); i++)
    test_register_functions[i] ();

  timer = g_timer_new ();
  result = g_test_run ();
  t = g_timer_elapsed (timer, NULL);
  num_tests = get_number_of_tests_in_suite (g_test_get_root ());
  g_timer_destroy (timer);

  g_print ("\nRan %d tests in %.2f seconds\n", num_tests, t);

#ifdef G_OS_WIN32
  if (IsDebuggerPresent ())
  {
    g_print ("\nPress a key to exit.\n");
    _getch ();
  }
#endif

  return result;
}

/* HACK */
struct GTestSuite
{
  gchar  *name;
  GSList *suites;
  GSList *cases;
};

static guint
get_number_of_tests_in_suite (GTestSuite * suite)
{
  guint total;
  GSList * walk;

  total = g_slist_length (suite->cases);
  for (walk = suite->suites; walk != NULL; walk = walk->next)
    total += get_number_of_tests_in_suite (walk->data);

  return total;
}

