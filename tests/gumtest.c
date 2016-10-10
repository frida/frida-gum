/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define DEBUG_HEAP_LEAKS 0

#include "testutil.h"

#include "gumscriptbackend.h"
#ifdef HAVE_I386
# include "lowlevel-helpers.h"
#endif
#include "valgrind.h"

#include <capstone.h>
#include <glib.h>
#include <gio/gio.h>
#include <gum/gum.h>
#include <string.h>

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
#if !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  GMemVTable mem_vtable = {
    gum_malloc,
    gum_realloc,
    gum_free,
    gum_calloc,
    gum_malloc,
    gum_realloc
  };
#endif
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

  gum_memory_init ();
#if !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  if (RUNNING_ON_VALGRIND)
  {
    g_setenv ("G_SLICE", "always-malloc", TRUE);
  }
  else
  {
    g_mem_set_vtable (&mem_vtable);
  }
#else
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
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

#ifdef HAVE_ASAN
  {
    const gchar * asan_options;

    asan_options = g_getenv ("ASAN_OPTIONS");
    if (asan_options == NULL || strstr (asan_options, "handle_segv=0") == NULL)
    {
      g_printerr (
          "\n"
          "You must disable AddressSanitizer's segv-handling. For example:\n"
          "\n"
          "$ export ASAN_OPTIONS=handle_segv=0\n"
          "\n"
          "This is required for testing Gum's exception-handling.\n"
          "\n");
      exit (1);
    }
  }
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4210)
#endif

  /* Core */
  TEST_RUN_LIST (testutil);
  TEST_RUN_LIST (tls);
  TEST_RUN_LIST (memory);
  TEST_RUN_LIST (process);
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TEST_RUN_LIST (symbolutil);
#endif
  TEST_RUN_LIST (codewriter);
  if (cs_support (CS_ARCH_X86))
    TEST_RUN_LIST (relocator);
  TEST_RUN_LIST (armwriter);
  if (cs_support (CS_ARCH_ARM))
    TEST_RUN_LIST (armrelocator);
  TEST_RUN_LIST (thumbwriter);
  if (cs_support (CS_ARCH_ARM))
    TEST_RUN_LIST (thumbrelocator);
  TEST_RUN_LIST (arm64writer);
  if (cs_support (CS_ARCH_ARM64))
    TEST_RUN_LIST (arm64relocator);
  TEST_RUN_LIST (interceptor);
#ifdef HAVE_DARWIN
  TEST_RUN_LIST (interceptor_darwin);
#endif
#if defined (HAVE_I386) && defined (G_OS_WIN32)
  TEST_RUN_LIST (memoryaccessmonitor);
#endif
#ifdef HAVE_I386
  TEST_RUN_LIST (stalker);
#endif
#ifdef HAVE_MAC
  TEST_RUN_LIST (stalker_mac);
#endif
  TEST_RUN_LIST (api_resolver);
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && !(defined (HAVE_MIPS))
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
#if !defined (HAVE_IOS) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TEST_RUN_LIST (sampler);
#endif
#ifdef G_OS_WIN32
  TEST_RUN_LIST (profiler);
#endif

#if defined (HAVE_GUMJS)
  /* GumJS */
  {
# ifdef HAVE_V8
    GumScriptBackend * v8_backend;

#  ifndef HAVE_ASAN
    v8_backend = gum_script_backend_obtain_v8 ();
#  else
    v8_backend = NULL;
#  endif

    if (v8_backend != NULL)
      TEST_RUN_LIST_WITH_DATA (script, v8_backend);
# endif
    TEST_RUN_LIST_WITH_DATA (script, gum_script_backend_obtain_duk ());

# ifdef HAVE_DARWIN
#  ifdef HAVE_V8
    if (v8_backend != NULL)
      TEST_RUN_LIST_WITH_DATA (script_darwin, v8_backend);
#  endif

    TEST_RUN_LIST_WITH_DATA (script_darwin, gum_script_backend_obtain_duk ());
# endif

# ifdef HAVE_ANDROID
#  ifdef HAVE_V8
    TEST_RUN_LIST_WITH_DATA (script_android, v8_backend);
#  endif
# endif

    if (gum_kernel_api_is_available ())
      TEST_RUN_LIST (kscript);
  }
#endif

#if defined (HAVE_GUMPP) && defined (G_OS_WIN32)
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

#if DEBUG_HEAP_LEAKS || defined (HAVE_ASAN)
  {
    GMainContext * context;

    context = g_main_context_get_thread_default ();
    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);
  }

# if GLIB_CHECK_VERSION (2, 46, 0)
  gio_shutdown ();
  glib_shutdown ();
# endif

  _test_util_deinit ();

# ifdef HAVE_I386
  lowlevel_helpers_deinit ();
# endif

  gum_deinit ();
# if GLIB_CHECK_VERSION (2, 46, 0)
  gio_deinit ();
  glib_deinit ();
# endif
  gum_memory_deinit ();

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
  GSList * cur;

  total = g_slist_length (suite->cases);
  for (cur = suite->suites; cur != NULL; cur = cur->next)
    total += get_number_of_tests_in_suite (cur->data);

  return total;
}

#ifdef HAVE_ANDROID

void
ClaimSignalChain (int signal,
                  struct sigaction * oldaction)
{
  /* g_print ("ClaimSignalChain(signal=%d)\n", signal); */
}

void
UnclaimSignalChain (int signal)
{
  /* g_print ("UnclaimSignalChain(signal=%d)\n", signal); */
}

void
InvokeUserSignalHandler (int signal,
                         siginfo_t * info,
                         void * context)
{
  /* g_print ("InvokeUserSignalHandler(signal=%d)\n", signal); */
}

void
InitializeSignalChain (void)
{
  /* g_print ("InitializeSignalChain()\n"); */
}

void
EnsureFrontOfChain (int signal,
                    struct sigaction * expected_action)
{
  /* g_print ("EnsureFrontOfChain(signal=%d)\n", signal); */
}

void
SetSpecialSignalHandlerFn (int signal,
                           gpointer fn)
{
  /* g_print ("SetSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

#endif
