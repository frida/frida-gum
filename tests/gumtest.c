/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define DEBUG_HEAP_LEAKS 0

#include "testutil.h"

#ifdef HAVE_I386
# include "lowlevel-helpers.h"
#endif

#include <glib.h>
#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
# include <windows.h>
# include <conio.h>
# include <crtdbg.h>
# include <stdio.h>
#endif

#ifdef HAVE_DARWIN
# include <dlfcn.h>
#endif

static guint get_number_of_tests_in_suite (GTestSuite * suite);

gint
main (gint argc, gchar * argv[])
{
  gint result;
  GTimer * timer;
  guint num_tests;
  gdouble t;

#if defined (G_OS_WIN32) && DEBUG_HEAP_LEAKS
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

#ifdef HAVE_DARWIN
  /* Simulate an application where CoreFoundation is available */
  dlopen ("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
      RTLD_LAZY | RTLD_GLOBAL);
#endif

  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
  /* needed for the above and GUM's heap library */
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#if GLIB_CHECK_VERSION (2, 46, 0)
  glib_init ();
  gio_init ();
#endif
  g_test_init (&argc, &argv, NULL);
  gum_init ();

  _test_util_init ();
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
#ifndef HAVE_QNX
  TEST_RUN_LIST (symbolutil);
#endif
  TEST_RUN_LIST (codewriter);
  TEST_RUN_LIST (relocator);
  TEST_RUN_LIST (armwriter);
  TEST_RUN_LIST (armrelocator);
  TEST_RUN_LIST (thumbwriter);
  TEST_RUN_LIST (thumbrelocator);
  TEST_RUN_LIST (arm64writer);
  TEST_RUN_LIST (arm64relocator);
  TEST_RUN_LIST (interceptor);
#if defined (HAVE_I386) && defined (G_OS_WIN32)
  TEST_RUN_LIST (memoryaccessmonitor);
#endif
#ifdef HAVE_I386
  TEST_RUN_LIST (stalker);
#endif
#ifdef HAVE_MAC
  TEST_RUN_LIST (stalker_mac);
#endif
#ifndef HAVE_QNX
  TEST_RUN_LIST (backtracer);
#endif

  /* Heap */
  TEST_RUN_LIST (allocation_tracker);
#ifdef G_OS_WIN32
  TEST_RUN_LIST (allocator_probe);
  TEST_RUN_LIST (allocator_probe_cxx);
  TEST_RUN_LIST (cobjecttracker);
  TEST_RUN_LIST (instancetracker);
#endif
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
#ifdef G_OS_WIN32
    TEST_RUN_LIST (boundschecker);
#endif
  }
#ifdef G_OS_WIN32
  TEST_RUN_LIST (sanitychecker);
#endif

  /* Prof */
#ifndef HAVE_IOS
  TEST_RUN_LIST (sampler);
#endif
#ifdef G_OS_WIN32
  TEST_RUN_LIST (profiler);
#endif

#if defined (HAVE_GUMJS) && !defined (HAVE_QNX)
  /* GumJS */
  TEST_RUN_LIST (script);
# ifdef HAVE_DARWIN
  TEST_RUN_LIST (script_darwin);
# endif
#endif

#ifdef G_OS_WIN32
  /* Gum++ */
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

#if DEBUG_HEAP_LEAKS
  _test_util_deinit ();

# ifdef HAVE_I386
  lowlevel_helpers_deinit ();
# endif

  gum_deinit ();
# if GLIB_CHECK_VERSION (2, 46, 0)
  gio_deinit ();
  glib_deinit ();
# endif

# ifdef G_OS_WIN32
  WSACleanup ();
# endif
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
