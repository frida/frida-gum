/*
 * Copyright (C) 2008-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "interceptor-callbacklistener.c"
#include "lowlevel-helpers.h"
#include "testutil.h"

#include <stdlib.h>
#include <string.h>

#ifdef G_OS_WIN32
# include "targetfunctions.c"
#else
# include <dlfcn.h>
#endif

#define INTERCEPTOR_TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define INTERCEPTOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Interceptor", test_interceptor, NAME, \
        TestInterceptorFixture)

/* TODO: fix this in GLib */
#ifdef HAVE_DARWIN
# undef G_MODULE_SUFFIX
# define G_MODULE_SUFFIX "dylib"
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_TEST_SHLIB_FLAVOR "ia32"
# else
#  define GUM_TEST_SHLIB_FLAVOR "amd64"
# endif
#elif defined (HAVE_ARM)
# define GUM_TEST_SHLIB_FLAVOR "arm"
#elif defined (HAVE_ARM64)
# define GUM_TEST_SHLIB_FLAVOR "arm64"
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
  guint last_thread_id;
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
                            listener_context_iface_init));

gpointer (* target_function) (GString * str) = NULL;
gpointer (* target_nop_function_a) (gpointer data);
gpointer (* target_nop_function_b) (gpointer data);
gpointer (* target_nop_function_c) (gpointer data);

gpointer (* special_function) (GString * str) = NULL;

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  (void) data;

  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_new ("");
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
        "targetfunctions-" GUM_TEST_SHLIB_FLAVOR "." G_MODULE_SUFFIX,
        NULL);
    lib = dlopen (filename, RTLD_NOW | RTLD_GLOBAL);
    if (lib == NULL)
      g_print ("failed to open '%s'\n", filename);
    g_assert (lib != NULL);
    g_free (filename);

    target_function = dlsym (lib, "gum_test_target_function");
    g_assert (target_function != NULL);

    target_nop_function_a = dlsym (lib, "gum_test_target_nop_function_a");
    g_assert (target_nop_function_a != NULL);

    target_nop_function_b = dlsym (lib, "gum_test_target_nop_function_b");
    g_assert (target_nop_function_b != NULL);

    target_nop_function_c = dlsym (lib, "gum_test_target_nop_function_c");
    g_assert (target_nop_function_c != NULL);

    filename = g_build_filename (testdir,
        "specialfunctions-" GUM_TEST_SHLIB_FLAVOR "." G_MODULE_SUFFIX,
        NULL);
    lib = dlopen (filename, RTLD_LAZY | RTLD_GLOBAL);
    g_assert (lib != NULL);
    g_free (filename);

    special_function = dlsym (lib, "gum_test_special_function");
    g_assert (special_function != NULL);

    g_free (testdir);
#endif
  }
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  guint i;

  (void) data;

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

  if (h->listener_context[listener_index] != NULL)
  {
    g_object_unref (h->listener_context[listener_index]);
    h->listener_context[listener_index] = NULL;
  }

  ctx = (ListenerContext *) g_object_new (listener_context_get_type (), NULL);
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
  (void) klass;
}

static void
listener_context_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = listener_context_on_enter;
  iface->on_leave = listener_context_on_leave;
}

static void
listener_context_init (ListenerContext * self)
{
  (void) self;
}

#ifdef G_OS_WIN32
static gpointer hit_target_function_repeatedly (gpointer data);
#endif
static gpointer replacement_malloc (gsize size);
static gpointer replacement_malloc_calling_malloc_and_replaced_free (
    gsize size);
static void replacement_free_doing_nothing (gpointer mem);
