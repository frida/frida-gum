/*
 * Copyright (C) 2008-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum.h"

#include "gum-init.h"
#include "../libs/gum/heap/gumallocatorprobe-priv.h"
#include "guminterceptor-priv.h"
#include "gumprintf.h"
#include "gumtls-priv.h"
#include "valgrind.h"

#include <capstone.h>
#include <glib-object.h>
#include <gio/gio.h>

#define DEBUG_HEAP_LEAKS 0

static void gum_destructor_invoke (GumDestructorFunc destructor);

static void gum_on_assert_failure (const gchar * log_domain, const gchar * file,
    gint line, const gchar * func, const gchar * message, gpointer user_data);
static void gum_on_log_message (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer user_data);

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
# include <dlfcn.h>
# define GUM_RTLD_DLOPEN 0x80000000
extern void * __libc_dlopen_mode (char * name, int flags);
static void gum_libdl_prevent_unload (void);
#endif

#ifdef HAVE_ANDROID
# include <android/log.h>
#else
# include <stdio.h>
# ifdef HAVE_DARWIN
#  include <CoreFoundation/CoreFoundation.h>
#  include <dlfcn.h>

typedef struct _GumCFApi GumCFApi;
typedef gint32 CFLogLevel;

enum _CFLogLevel
{
  kCFLogLevelEmergency = 0,
  kCFLogLevelAlert     = 1,
  kCFLogLevelCritical  = 2,
  kCFLogLevelError     = 3,
  kCFLogLevelWarning   = 4,
  kCFLogLevelNotice    = 5,
  kCFLogLevelInfo      = 6,
  kCFLogLevelDebug     = 7
};

struct _GumCFApi
{
  CFStringRef (* CFStringCreateWithCString) (CFAllocatorRef alloc,
      const char * c_str, CFStringEncoding encoding);
  void (* CFRelease) (CFTypeRef cf);
  void (* CFLog) (CFLogLevel level, CFStringRef format, ...);
};

# endif
#endif

static void gum_do_init (void);

static gboolean gum_initialized = FALSE;
static GSList * gum_destructors = NULL;

void
gum_init (void)
{
  if (gum_initialized)
    return;
  gum_initialized = TRUE;

  gum_do_init ();
}

void
gum_deinit (void)
{
  g_assert (gum_initialized);

  _gum_tls_deinit ();

  g_slist_foreach (gum_destructors, (GFunc) gum_destructor_invoke, NULL);
  g_slist_free (gum_destructors);
  gum_destructors = NULL;

  _gum_allocator_probe_deinit ();

  _gum_interceptor_deinit ();

  gum_initialized = FALSE;
}

static void
gum_do_init (void)
{
  cs_opt_mem gum_cs_mem_callbacks = {
    gum_malloc,
    gum_calloc,
    gum_realloc,
    gum_free,
    gum_vsnprintf
  };

  gum_memory_init ();

  glib_init ();
  gobject_init ();
  gio_init ();

  cs_option (0, CS_OPT_MEM, GPOINTER_TO_SIZE (&gum_cs_mem_callbacks));

  _gum_tls_init ();
  _gum_interceptor_init ();
  _gum_tls_realize ();
}

void
_gum_register_destructor (GumDestructorFunc destructor)
{
  gum_destructors = g_slist_prepend (gum_destructors,
      GUM_FUNCPTR_TO_POINTER (destructor));
}

static void
gum_destructor_invoke (GumDestructorFunc destructor)
{
  destructor ();
}

void
gum_init_embedded (void)
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
#if defined (G_OS_WIN32) && DEBUG_HEAP_LEAKS
  int tmp_flag;
#endif

  if (gum_initialized)
    return;
  gum_initialized = TRUE;

#if defined (G_OS_WIN32) && DEBUG_HEAP_LEAKS
  /*_CrtSetBreakAlloc (1337);*/

  _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

  tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
  tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
  tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

  _CrtSetDbgFlag (tmp_flag);
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
  glib_init ();
  g_assertion_set_handler (gum_on_assert_failure, NULL);
  g_log_set_default_handler (gum_on_log_message, NULL);
  g_log_set_always_fatal (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL |
      G_LOG_LEVEL_WARNING);
  gum_do_init ();

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
  gum_libdl_prevent_unload ();
#endif
}

void
gum_deinit_embedded (void)
{
  g_assert (gum_initialized);

  gio_shutdown ();
  glib_shutdown ();

  gum_deinit ();
  gio_deinit ();
  glib_deinit ();
  gum_memory_deinit ();

  gum_initialized = FALSE;
}

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)

static void
gum_libdl_prevent_unload (void)
{
  __libc_dlopen_mode ("libdl.so.2", RTLD_LAZY | GUM_RTLD_DLOPEN);
}

#endif

static void
gum_on_assert_failure (const gchar * log_domain,
                       const gchar * file,
                       gint line,
                       const gchar * func,
                       const gchar * message,
                       gpointer user_data)
{
  gchar * full_message;

  while (g_str_has_prefix (file, ".." G_DIR_SEPARATOR_S))
    file += 3;
  if (message == NULL)
    message = "code should not be reached";

  full_message = g_strdup_printf ("%s:%d:%s%s %s", file, line, func,
      (func[0] != '\0') ? ":" : "", message);
  gum_on_log_message (log_domain, G_LOG_LEVEL_ERROR, full_message, user_data);
  g_free (full_message);

  abort ();
}

static void
gum_on_log_message (const gchar * log_domain,
                    GLogLevelFlags log_level,
                    const gchar * message,
                    gpointer user_data)
{
#ifdef HAVE_ANDROID
  int priority;

  (void) user_data;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
    case G_LOG_LEVEL_CRITICAL:
    case G_LOG_LEVEL_WARNING:
      priority = ANDROID_LOG_FATAL;
      break;
    case G_LOG_LEVEL_MESSAGE:
    case G_LOG_LEVEL_INFO:
      priority = ANDROID_LOG_INFO;
      break;
    case G_LOG_LEVEL_DEBUG:
      priority = ANDROID_LOG_DEBUG;
      break;
    default:
      g_assert_not_reached ();
  }

  __android_log_write (priority, log_domain, message);
#else
# ifdef HAVE_DARWIN
  static gsize api_value = 0;
  GumCFApi * api;

  if (g_once_init_enter (&api_value))
  {
    const gchar * cf_path = "/System/Library/Frameworks/"
        "CoreFoundation.framework/CoreFoundation";
    void * cf;

    /*
     * CoreFoundation must be loaded by the main thread, so we should avoid
     * loading it.
     */
    if (gum_module_find_base_address (cf_path) != 0)
    {
      cf = dlopen (cf_path, RTLD_GLOBAL | RTLD_LAZY);
      g_assert (cf != NULL);

      api = g_slice_new (GumCFApi);

      api->CFStringCreateWithCString = dlsym (cf, "CFStringCreateWithCString");
      g_assert (api->CFStringCreateWithCString != NULL);

      api->CFRelease = dlsym (cf, "CFRelease");
      g_assert (api->CFRelease != NULL);

      api->CFLog = dlsym (cf, "CFLog");
      g_assert (api->CFLog != NULL);

      dlclose (cf);
    }
    else
    {
      api = NULL;
    }

    g_once_init_leave (&api_value, 1 + GPOINTER_TO_SIZE (api));
  }

  api = GSIZE_TO_POINTER (api_value - 1);
  if (api != NULL)
  {
    CFLogLevel cf_log_level;
    CFStringRef message_str, template_str;

    switch (log_level & G_LOG_LEVEL_MASK)
    {
      case G_LOG_LEVEL_ERROR:
        cf_log_level = kCFLogLevelError;
        break;
      case G_LOG_LEVEL_CRITICAL:
        cf_log_level = kCFLogLevelCritical;
        break;
      case G_LOG_LEVEL_WARNING:
        cf_log_level = kCFLogLevelWarning;
        break;
      case G_LOG_LEVEL_MESSAGE:
        cf_log_level = kCFLogLevelNotice;
        break;
      case G_LOG_LEVEL_INFO:
        cf_log_level = kCFLogLevelInfo;
        break;
      case G_LOG_LEVEL_DEBUG:
        cf_log_level = kCFLogLevelDebug;
        break;
      default:
        g_assert_not_reached ();
    }

    message_str = api->CFStringCreateWithCString (NULL, message,
        kCFStringEncodingUTF8);
    if (log_domain != NULL)
    {
      CFStringRef log_domain_str;

      template_str = api->CFStringCreateWithCString (NULL, "%@: %@",
          kCFStringEncodingUTF8);
      log_domain_str = api->CFStringCreateWithCString (NULL, log_domain,
          kCFStringEncodingUTF8);
      api->CFLog (cf_log_level, template_str, log_domain_str, message_str);
      api->CFRelease (log_domain_str);
    }
    else
    {
      template_str = api->CFStringCreateWithCString (NULL, "%@",
          kCFStringEncodingUTF8);
      api->CFLog (cf_log_level, template_str, message_str);
    }
    api->CFRelease (template_str);
    api->CFRelease (message_str);

    return;
  }
  /* else: fall through to stdout/stderr logging */
# endif

  FILE * file = NULL;
  const gchar * severity = NULL;

  (void) user_data;

  switch (log_level & G_LOG_LEVEL_MASK)
  {
    case G_LOG_LEVEL_ERROR:
      file = stderr;
      severity = "ERROR";
      break;
    case G_LOG_LEVEL_CRITICAL:
      file = stderr;
      severity = "CRITICAL";
      break;
    case G_LOG_LEVEL_WARNING:
      file = stderr;
      severity = "WARNING";
      break;
    case G_LOG_LEVEL_MESSAGE:
      file = stderr;
      severity = "MESSAGE";
      break;
    case G_LOG_LEVEL_INFO:
      file = stdout;
      severity = "INFO";
      break;
    case G_LOG_LEVEL_DEBUG:
      file = stdout;
      severity = "DEBUG";
      break;
    default:
      g_assert_not_reached ();
  }

  fprintf (file, "[%s %s] %s\n", log_domain, severity, message);
  fflush (file);
#endif
}
