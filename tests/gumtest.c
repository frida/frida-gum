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
#include <stdio.h>
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

#ifdef G_OS_WIN32
  {
    WORD version_requested = MAKEWORD (2, 2);
    WSADATA wsa_data;
    int err;

    err = WSAStartup (version_requested, &wsa_data);
    g_assert_cmpint (err, ==, 0);
  }
#endif

  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
  /* needed for the above and GUM's heap library */
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#ifdef _DEBUG
  g_thread_init_with_errorcheck_mutexes (NULL);
#else
  g_thread_init (NULL);
#endif
  g_type_init ();
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
  TEST_RUN_LIST (memory);
  TEST_RUN_LIST (process);
  TEST_RUN_LIST (symbolutil);
#ifdef HAVE_I386
  TEST_RUN_LIST (codewriter);
  TEST_RUN_LIST (functionparser);
  TEST_RUN_LIST (relocator);
#endif
#ifdef HAVE_ARM
  TEST_RUN_LIST (armwriter);
  TEST_RUN_LIST (armrelocator);
  TEST_RUN_LIST (thumbwriter);
  TEST_RUN_LIST (thumbrelocator);
#endif
  TEST_RUN_LIST (closure);
  TEST_RUN_LIST (interceptor);
#if defined (HAVE_V8)
  TEST_RUN_LIST (script);
#endif
#if defined (HAVE_I386) && defined (G_OS_WIN32)
  TEST_RUN_LIST (memoryaccessmonitor);
#endif
#ifndef HAVE_ARM
  TEST_RUN_LIST (stalker);
#endif
#if !defined (HAVE_ANDROID) && !defined (HAVE_IOS)
  TEST_RUN_LIST (backtracer);
#endif

#ifdef HAVE_LIBS
  /* Heap */
  TEST_RUN_LIST (allocation_tracker);
  TEST_RUN_LIST (allocator_probe);
  TEST_RUN_LIST (allocator_probe_cxx);
  TEST_RUN_LIST (cobjecttracker);
  TEST_RUN_LIST (instancetracker);
  TEST_RUN_LIST (pagepool);
#ifndef G_OS_WIN32
  if (gum_is_debugger_present ())
  {
    g_print (
        "\n"
        "***\n"
        "NOTE: Skipping BoundsChecker tests because debugger is attached\n"
        "***\n"
        "\n");
  }
  else
#endif
  {
    TEST_RUN_LIST (boundschecker);
  }
  TEST_RUN_LIST (sanitychecker);

  /* Prof */
  TEST_RUN_LIST (sampler);
  TEST_RUN_LIST (profiler);
#endif

  /* GUM++ */
#ifdef HAVE_BINDINGS
  TEST_RUN_LIST (gumpp_backtracer);
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

  {
    GMainContext * context;

    context = g_main_context_get_thread_default ();
    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);
  }

  _test_util_deinit ();

#ifdef HAVE_I386
  lowlevel_helpers_deinit ();
#endif

  gum_deinit ();
#if GLIB_CHECK_VERSION (2, 27, 1)
  g_test_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();
#endif

#ifdef G_OS_WIN32
  WSACleanup ();
#endif

#if defined (G_OS_WIN32) && !DEBUG_HEAP_LEAKS
  if (IsDebuggerPresent ())
  {
    printf ("\nPress a key to exit.\n");
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
