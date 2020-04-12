/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define DEBUG_HEAP_LEAKS 0

#include "testutil.h"

#if defined (HAVE_GUMJS)
# include "gumscriptbackend.h"
#endif
#ifdef HAVE_I386
# include "lowlevelhelpers.h"
#endif
#include "valgrind.h"

#include <capstone.h>
#include <glib.h>
#include <gio/gio.h>
#ifdef HAVE_GLIB_SCHANNEL_STATIC
# include <glib-schannel-static.h>
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
# include <glib-openssl-static.h>
#endif
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

  gum_internal_heap_ref ();
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
  glib_init ();
  gio_init ();
#ifdef HAVE_GLIB_SCHANNEL_STATIC
  g_io_module_schannel_register ();
#endif
#ifdef HAVE_GLIB_OPENSSL_STATIC
  g_io_module_openssl_register ();
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

#ifdef HAVE_IOS
  if (g_file_test ("/usr/lib/libjailbreak.dylib", G_FILE_TEST_EXISTS))
  {
    GModule * module;
    void (* entitle_now) (pid_t pid);

    module = g_module_open ("/usr/lib/libjailbreak.dylib", G_MODULE_BIND_LAZY);

    entitle_now = NULL;
    g_module_symbol (module, "jb_oneshot_entitle_now",
        (gpointer *) &entitle_now);

    entitle_now (getpid ());

    g_module_close (module);
  }
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4210)
#endif

  /* Core */
  TESTLIST_REGISTER (testutil);
  TESTLIST_REGISTER (tls);
  TESTLIST_REGISTER (cloak);
  TESTLIST_REGISTER (memory);
  TESTLIST_REGISTER (process);
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTLIST_REGISTER (symbolutil);
#endif
  TESTLIST_REGISTER (codewriter);
  if (cs_support (CS_ARCH_X86))
    TESTLIST_REGISTER (relocator);
  TESTLIST_REGISTER (armwriter);
  if (cs_support (CS_ARCH_ARM))
    TESTLIST_REGISTER (armrelocator);
  TESTLIST_REGISTER (thumbwriter);
  if (cs_support (CS_ARCH_ARM))
    TESTLIST_REGISTER (thumbrelocator);
  TESTLIST_REGISTER (arm64writer);
  if (cs_support (CS_ARCH_ARM64))
    TESTLIST_REGISTER (arm64relocator);
  TESTLIST_REGISTER (interceptor);
#ifdef HAVE_DARWIN
  TESTLIST_REGISTER (interceptor_darwin);
#endif
#ifdef HAVE_ANDROID
  TESTLIST_REGISTER (interceptor_android);
#endif
#ifdef HAVE_ARM
  TESTLIST_REGISTER (interceptor_arm);
#endif
#ifdef HAVE_ARM64
  TESTLIST_REGISTER (interceptor_arm64);
#endif
#ifdef HAVE_DARWIN
  TESTLIST_REGISTER (exceptor_darwin);
#endif
  TESTLIST_REGISTER (memoryaccessmonitor);

  if (gum_stalker_is_supported ())
  {
#if defined (HAVE_I386) || defined (HAVE_ARM64) || defined (HAVE_ARM)
    TESTLIST_REGISTER (stalker);
#endif
#ifdef HAVE_MACOS
    TESTLIST_REGISTER (stalker_macos);
#endif
#if defined (HAVE_ARM64) && defined (HAVE_DARWIN)
    TESTLIST_REGISTER (stalker_darwin);
#endif
  }

  TESTLIST_REGISTER (api_resolver);
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && !(defined (HAVE_MIPS))
  TESTLIST_REGISTER (backtracer);
#endif

  /* Heap */
  TESTLIST_REGISTER (allocation_tracker);
#ifdef G_OS_WIN32
  TESTLIST_REGISTER (allocator_probe);
  TESTLIST_REGISTER (allocator_probe_cxx);
  TESTLIST_REGISTER (cobjecttracker);
  TESTLIST_REGISTER (instancetracker);
#endif
  TESTLIST_REGISTER (pagepool);
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
    TESTLIST_REGISTER (boundschecker);
#endif
  }
#ifdef G_OS_WIN32
  TESTLIST_REGISTER (sanitychecker);
#endif

  /* Prof */
#if !defined (HAVE_IOS) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTLIST_REGISTER (sampler);
#endif
#ifdef G_OS_WIN32
  TESTLIST_REGISTER (profiler);
#endif

#if defined (HAVE_GUMJS)
  /* GumJS */
  {
    GumScriptBackend * duk_backend, * v8_backend;

    duk_backend = gum_script_backend_obtain_duk ();
    if (duk_backend != NULL)
      TESTLIST_REGISTER_WITH_DATA (script, duk_backend);

# ifndef HAVE_ASAN
    v8_backend = gum_script_backend_obtain_v8 ();
# else
    v8_backend = NULL;
# endif
    if (v8_backend != NULL)
      TESTLIST_REGISTER_WITH_DATA (script, v8_backend);

# ifndef HAVE_ASAN
    if (g_test_slow () && gum_kernel_api_is_available ())
      TESTLIST_REGISTER (kscript);
# endif
  }
#endif

#if defined (HAVE_GUMPP) && defined (G_OS_WIN32)
  /* Gum++ */
  TESTLIST_REGISTER (gumpp_backtracer);
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

  gum_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  _test_util_deinit ();

# ifdef HAVE_I386
  lowlevel_helpers_deinit ();
# endif

  gum_deinit ();
  gio_deinit ();
  glib_deinit ();
  gum_internal_heap_unref ();

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

void
AddSpecialSignalHandlerFn (int signal,
                           gpointer sa)
{
  /* g_print ("AddSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

void
RemoveSpecialSignalHandlerFn (int signal,
                              bool (* fn) (int, siginfo_t *, void *))
{
  /* g_print ("RemoveSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

#endif
