/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "interceptor-callbacklistener.c"
#include "lowlevel-helpers.h"
#include "testutil.h"
#include "valgrind.h"

#include <stdlib.h>
#include <string.h>

#ifdef G_OS_WIN32
# include "targetfunctions.c"
#else
# include <dlfcn.h>
# include <unistd.h>
#endif

#define TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Interceptor", \
        test_interceptor, NAME, TestInterceptorFixture)

/* TODO: fix this in GLib */
#ifdef HAVE_DARWIN
# undef G_MODULE_SUFFIX
# define G_MODULE_SUFFIX "dylib"
#endif

#if defined (G_OS_WIN32)
# define GUM_TEST_SHLIB_OS "windows"
#elif defined (HAVE_MACOS)
# define GUM_TEST_SHLIB_OS "macos"
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
# define GUM_TEST_SHLIB_OS "linux"
#elif defined (HAVE_IOS)
# define GUM_TEST_SHLIB_OS "ios"
#elif defined (HAVE_ANDROID)
# define GUM_TEST_SHLIB_OS "android"
#elif defined (HAVE_QNX)
# define GUM_TEST_SHLIB_OS "qnx"
#else
# error Unknown OS
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_TEST_SHLIB_ARCH "x86"
# else
#  define GUM_TEST_SHLIB_ARCH "x86_64"
# endif
#elif defined (HAVE_ARM)
# define GUM_TEST_SHLIB_ARCH "arm"
#elif defined (HAVE_ARM64)
# define GUM_TEST_SHLIB_ARCH "arm64"
#elif defined (HAVE_MIPS)
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#  if GLIB_SIZEOF_VOID_P == 8
#    define GUM_TEST_SHLIB_ARCH "mips64el"
#  else
#    define GUM_TEST_SHLIB_ARCH "mipsel"
#  endif
# else
#  if GLIB_SIZEOF_VOID_P == 8
#    define GUM_TEST_SHLIB_ARCH "mips64"
#  else
#    define GUM_TEST_SHLIB_ARCH "mips"
#  endif
# endif
#else
# error Unknown CPU
#endif

typedef struct _TestInterceptorFixture   TestInterceptorFixture;
typedef struct _ListenerContext      ListenerContext;
typedef struct _ListenerContextClass ListenerContextClass;

typedef gpointer (* InterceptorTestFunc) (gpointer data);

struct _ListenerContext
{
  GObject parent;

  TestInterceptorFixture * harness;
  gchar enter_char;
  gchar leave_char;
  GumThreadId last_thread_id;
  gsize last_seen_argument;
  gpointer last_return_value;
  GumCpuContext last_on_enter_cpu_context;
};

struct _ListenerContextClass
{
  GObjectClass parent_class;
};

struct _TestInterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  ListenerContext * listener_context[2];
};

static void listener_context_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (ListenerContext,
                        listener_context,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            listener_context_iface_init))

gpointer (* target_function) (GString * str) = NULL;
gpointer (* target_nop_function_a) (gpointer data);
gpointer (* target_nop_function_b) (gpointer data);
gpointer (* target_nop_function_c) (gpointer data);

gpointer (* special_function) (GString * str) = NULL;

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);
  memset (&fixture->listener_context, 0, sizeof (fixture->listener_context));

  if (target_function == NULL)
  {
#ifdef G_OS_WIN32
    target_function = gum_test_target_function;
    special_function = gum_test_target_function;
    target_nop_function_a = gum_test_target_nop_function_a;
    target_nop_function_b = gum_test_target_nop_function_b;
    target_nop_function_c = gum_test_target_nop_function_c;
#else
    gchar * testdir, * filename;
    void * lib;

    testdir = test_util_get_data_dir ();

    filename = g_build_filename (testdir,
        "targetfunctions-" GUM_TEST_SHLIB_OS "-" GUM_TEST_SHLIB_ARCH
        "." G_MODULE_SUFFIX, NULL);
    lib = dlopen (filename, RTLD_NOW | RTLD_GLOBAL);
    if (lib == NULL)
      g_print ("failed to open '%s'\n", filename);
    g_assert_nonnull (lib);
    g_free (filename);

    target_function = dlsym (lib, "gum_test_target_function");
    g_assert_nonnull (target_function);

    target_nop_function_a = dlsym (lib, "gum_test_target_nop_function_a");
    g_assert_nonnull (target_nop_function_a);

    target_nop_function_b = dlsym (lib, "gum_test_target_nop_function_b");
    g_assert_nonnull (target_nop_function_b);

    target_nop_function_c = dlsym (lib, "gum_test_target_nop_function_c");
    g_assert_nonnull (target_nop_function_c);

    filename = g_build_filename (testdir,
        "specialfunctions-" GUM_TEST_SHLIB_OS "-" GUM_TEST_SHLIB_ARCH
        "." G_MODULE_SUFFIX, NULL);
    lib = dlopen (filename, RTLD_LAZY | RTLD_GLOBAL);
    g_assert_nonnull (lib);
    g_free (filename);

    special_function = dlsym (lib, "gum_test_special_function");
    g_assert_nonnull (special_function);

    g_free (testdir);
#endif
  }
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  guint i;

  for (i = 0; i < G_N_ELEMENTS (fixture->listener_context); i++)
  {
    ListenerContext * ctx = fixture->listener_context[i];

    if (ctx != NULL)
    {
      gum_interceptor_detach_listener (fixture->interceptor,
          GUM_INVOCATION_LISTENER (ctx));
      g_object_unref (ctx);
    }
  }

  g_string_free (fixture->result, TRUE);
  g_object_unref (fixture->interceptor);
}

GumAttachReturn
interceptor_fixture_try_attaching_listener (TestInterceptorFixture * h,
                                            guint listener_index,
                                            gpointer test_func,
                                            gchar enter_char,
                                            gchar leave_char)
{
  GumAttachReturn result;
  ListenerContext * ctx;

  g_clear_object (&h->listener_context[listener_index]);

  ctx = g_object_new (listener_context_get_type (), NULL);
  ctx->harness = h;
  ctx->enter_char = enter_char;
  ctx->leave_char = leave_char;

  result = gum_interceptor_attach_listener (h->interceptor, test_func,
      GUM_INVOCATION_LISTENER (ctx), NULL);
  if (result == GUM_ATTACH_OK)
  {
    h->listener_context[listener_index] = ctx;
  }
  else
  {
    g_object_unref (ctx);
  }

  return result;
}

void
interceptor_fixture_attach_listener (TestInterceptorFixture * h,
                                     guint listener_index,
                                     gpointer test_func,
                                     gchar enter_char,
                                     gchar leave_char)
{
  g_assert_cmpint (interceptor_fixture_try_attaching_listener (h,
      listener_index, test_func, enter_char, leave_char), ==,
      GUM_ATTACH_OK);
}

void
interceptor_fixture_detach_listener (TestInterceptorFixture * h,
                                     guint listener_index)
{
  gum_interceptor_detach_listener (h->interceptor,
    GUM_INVOCATION_LISTENER (h->listener_context[listener_index]));
}

gpointer
interceptor_fixture_get_libc_malloc (void)
{
  return gum_heap_api_list_get_nth (test_util_heap_apis (), 0)->malloc;
}

gpointer
interceptor_fixture_get_libc_free (void)
{
  return gum_heap_api_list_get_nth (test_util_heap_apis (), 0)->free;
}

static void
listener_context_on_enter (GumInvocationListener * listener,
                           GumInvocationContext * context)
{
  ListenerContext * self = (ListenerContext *) listener;

  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_ENTER);

  g_string_append_c (self->harness->result, self->enter_char);

  self->last_seen_argument = (gsize)
      gum_invocation_context_get_nth_argument (context, 0);
  self->last_on_enter_cpu_context = *context->cpu_context;

  self->last_thread_id = gum_invocation_context_get_thread_id (context);
}

static void
listener_context_on_leave (GumInvocationListener * listener,
                           GumInvocationContext * context)
{
  ListenerContext * self = (ListenerContext *) listener;

  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_LEAVE);

  g_string_append_c (self->harness->result, self->leave_char);

  self->last_return_value = gum_invocation_context_get_return_value (context);
}

static void
listener_context_class_init (ListenerContextClass * klass)
{
}

static void
listener_context_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = listener_context_on_enter;
  iface->on_leave = listener_context_on_leave;
}

static void
listener_context_init (ListenerContext * self)
{
}
