/*
 * Copyright (C) 2008-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum.h"

#include "gum-init.h"
#include "../libs/gum/heap/gumallocatorprobe-priv.h"
#include "guminterceptor-priv.h"
#include "gumlibc.h"
#include "gumprintf.h"
#include "gumtls-priv.h"
#include "valgrind.h"

#include <capstone.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <string.h>

#define DEBUG_HEAP_LEAKS 0

static gpointer do_init (gpointer data);
static void gum_destructor_invoke (GumDestructorFunc destructor);

static void gum_on_assert_failure (const gchar * log_domain, const gchar * file,
    gint line, const gchar * func, const gchar * message, gpointer user_data);
static void gum_on_log_message (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer user_data);

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
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

static void gum_capstone_deinit (void);
static gpointer gum_capstone_malloc (gsize size);
static gpointer gum_capstone_calloc (gsize count, gsize size);
static gpointer gum_capstone_realloc (gpointer mem, gsize size);
static void gum_capstone_free (gpointer mem);

static GSList * gum_destructors = NULL;

void
gum_init (void)
{
  static GOnce init_once = G_ONCE_INIT;
  g_once (&init_once, do_init, NULL);
}

void
gum_deinit (void)
{
  _gum_tls_deinit ();

  g_slist_foreach (gum_destructors, (GFunc) gum_destructor_invoke, NULL);
  g_slist_free (gum_destructors);
  gum_destructors = NULL;

  _gum_allocator_probe_deinit ();

  _gum_interceptor_deinit ();

  gum_capstone_deinit ();
}

static gpointer
do_init (gpointer data)
{
  cs_opt_mem gum_cs_mem_callbacks = {
    gum_capstone_malloc,
    gum_capstone_calloc,
    gum_capstone_realloc,
    gum_capstone_free,
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

  return NULL;
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
  gum_init ();

#if defined (HAVE_LINUX) && defined (HAVE_GLIBC)
  gum_libdl_prevent_unload ();
#endif
}

void
gum_deinit_embedded (void)
{
  gio_shutdown ();
  glib_shutdown ();

  gum_deinit ();
  gio_deinit ();
  glib_deinit ();
  gum_memory_deinit ();
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

typedef struct _GumPool GumPool;
typedef struct _GumBlock GumBlock;

struct _GumPool
{
  gsize block_size;
  GumBlock * free;
  GumPool * next;
};

struct _GumBlock
{
  GumPool * pool;
  GumBlock * next;
};

#define GUM_ALIGNED_SIZE(s) ((s + (16 - 1)) & ~(16 -1))
#define GUM_POOL_HEADER_SIZE GUM_ALIGNED_SIZE (sizeof (GumPool))
#define GUM_BLOCK_HEADER_SIZE GUM_ALIGNED_SIZE (sizeof (GumBlock))

#define GUM_BLOCK_TO_DATA_POINTER(b) \
    ((gpointer) ((guint8 *) b + GUM_BLOCK_HEADER_SIZE))
#define GUM_BLOCK_FROM_DATA_POINTER(p) \
    ((GumBlock *) ((guint8 *) p - GUM_BLOCK_HEADER_SIZE))

static GumPool * pools;

static void
gum_capstone_deinit (void)
{
  while (pools != NULL)
  {
    GumPool * next;

    next = pools->next;
    gum_free_pages (pools);
    pools = next;
  }
}

static gpointer
gum_capstone_malloc (gsize size)
{
  guint page_size;

  page_size = gum_query_page_size ();

  do
  {
    GumPool * head, * pool;
    GumBlock * block, * next_block;
    gsize aligned_block_size, pool_size, pages;
    gpointer pool_start, pool_end;

    head = pools;
    pool = NULL;
    for (pool = pools; pool != NULL; pool = pool->next)
    {
      if (pool->block_size == size)
      {
        do
        {
          block = pool->free;
          if (block == NULL)
            break;
        }
        while (!g_atomic_pointer_compare_and_exchange (&pool->free, block,
            block->next));

        if (block != NULL)
          return GUM_BLOCK_TO_DATA_POINTER (block);
      }
    }

    aligned_block_size = GUM_BLOCK_HEADER_SIZE + GUM_ALIGNED_SIZE (size);
    pool_size = GUM_POOL_HEADER_SIZE + (100 * aligned_block_size);
    pages = pool_size / page_size;
    if (pool_size % page_size != 0)
      pages++;

    pool_start = gum_alloc_n_pages (pages, GUM_PAGE_RW);
    pool_end = (guint8 *) pool_start + pool_size;
    pool = (GumPool *) pool_start;
    pool->block_size = size;
    block = (GumBlock *) ((guint8 *) pool_start + GUM_POOL_HEADER_SIZE);
    pool->free = block;
    do
    {
      next_block = (GumBlock *) ((guint8 *) block + aligned_block_size);
      if (next_block == pool_end)
        next_block = NULL;
      block->pool = pool;
      block->next = next_block;
      block = next_block;
    }
    while (next_block != NULL);
    pool->next = head;
    if (!g_atomic_pointer_compare_and_exchange (&pools, head, pool))
      gum_free_pages (pool);
  }
  while (TRUE);
}

static gpointer
gum_capstone_calloc (gsize count,
                     gsize size)
{
  gpointer result;
  gsize total;

  total = count * size;
  result = gum_capstone_malloc (total);
  gum_memset (result, 0, total);

  return result;
}

static gpointer
gum_capstone_realloc (gpointer mem,
                      gsize size)
{
  GumBlock * block;
  gpointer result;

  if (mem == NULL)
    return gum_capstone_malloc (size);

  block = GUM_BLOCK_FROM_DATA_POINTER (mem);

  result = gum_capstone_malloc (size);
  memcpy (result, mem, MIN (block->pool->block_size, size));
  gum_capstone_free (mem);

  return result;
}

static void
gum_capstone_free (gpointer mem)
{
  GumBlock * block, * next;
  GumPool * pool;

  if (mem == NULL)
    return;

  block = GUM_BLOCK_FROM_DATA_POINTER (mem);
  pool = block->pool;
  do
  {
    next = pool->free;
    block->next = next;
  }
  while (!g_atomic_pointer_compare_and_exchange (&pool->free, next, block));
}
