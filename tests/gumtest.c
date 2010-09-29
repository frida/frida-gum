/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#define DEBUG_HEAP_LEAKS 0

#include "testutil.h"

#ifdef HAVE_I386
#include "lowlevel-helpers.h"
#endif

#include <glib.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <conio.h>
#include <crtdbg.h>
#endif

static guint get_number_of_tests_in_suite (GTestSuite * suite);

gint
main (gint argc, gchar * argv[])
{
  gint result;
  GTimer * timer;
  guint num_tests;
  gdouble t;

#if DEBUG_HEAP_LEAKS
  {
    int tmp_flag;

    /*_CrtSetBreakAlloc (1337);*/

    _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

    tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

    tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
    tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
    tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

    _CrtSetDbgFlag (tmp_flag);
  }
#endif

  g_setenv ("G_SLICE", "always-malloc", TRUE);
  g_test_init (&argc, &argv, NULL);
  gum_init ();

#ifdef HAVE_I386
  lowlevel_helpers_init ();
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4210)
#endif

  /* Core */
  TEST_RUN_LIST (testutil);
  TEST_RUN_LIST (symbolutil);
#ifdef HAVE_I386
  TEST_RUN_LIST (codewriter);
  TEST_RUN_LIST (functionparser);
  TEST_RUN_LIST (relocator);
#endif
#ifdef HAVE_ARM
  TEST_RUN_LIST (thumbwriter);
  TEST_RUN_LIST (thumbrelocator);
#endif
  TEST_RUN_LIST (interceptor);
  TEST_RUN_LIST (script);
#ifdef HAVE_I386
  TEST_RUN_LIST (stalker);
  TEST_RUN_LIST (tracer);
  TEST_RUN_LIST (backtracer);

  /* Heap */
  TEST_RUN_LIST (allocation_tracker);
  TEST_RUN_LIST (allocator_probe);
  TEST_RUN_LIST (allocator_probe_cxx);
  TEST_RUN_LIST (cobjecttracker);
  TEST_RUN_LIST (instancetracker);
  TEST_RUN_LIST (pagepool);
  TEST_RUN_LIST (boundschecker);
  TEST_RUN_LIST (sanitychecker);

  /* Prof */
  TEST_RUN_LIST (sampler);
  TEST_RUN_LIST (profiler);
#endif

#ifdef _MSC_VER
#pragma warning (pop)
#endif

  timer = g_timer_new ();
  result = g_test_run ();
  t = g_timer_elapsed (timer, NULL);
  num_tests = get_number_of_tests_in_suite (g_test_get_root ());
  g_timer_destroy (timer);

  g_print ("\nRan %d tests in %.2f seconds\n", num_tests, t);

#ifdef HAVE_I386
  lowlevel_helpers_deinit ();
#endif

  gum_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_test_deinit ();

#if defined (G_OS_WIN32) && !DEBUG_HEAP_LEAKS
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
