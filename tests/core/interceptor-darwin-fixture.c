/*
 * Copyright (C) 2008-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "interceptor-callbacklistener.c"
#include "testutil.h"

#include <dlfcn.h>
#include <string.h>

#define INTERCEPTOR_TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define INTERCEPTOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Interceptor/Darwin", \
        test_interceptor, NAME, TestInterceptorFixture)

typedef struct _TestInterceptorFixture     TestInterceptorFixture;
typedef struct _DarwinListenerContext      DarwinListenerContext;
typedef struct _DarwinListenerContextClass DarwinListenerContextClass;

struct _DarwinListenerContext
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

struct _DarwinListenerContextClass
{
  GObjectClass parent_class;
};

struct _TestInterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  DarwinListenerContext * listener_context[2];
};

static void listener_context_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (DarwinListenerContext,
                        listener_context,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            listener_context_iface_init));

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  (void) data;

  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);
  memset (&fixture->listener_context, 0, sizeof (fixture->listener_context));
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  guint i;

  (void) data;

  for (i = 0; i < G_N_ELEMENTS (fixture->listener_context); i++)
  {
    DarwinListenerContext * ctx = fixture->listener_context[i];

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
  DarwinListenerContext * ctx;

  if (h->listener_context[listener_index] != NULL)
  {
    g_object_unref (h->listener_context[listener_index]);
    h->listener_context[listener_index] = NULL;
  }

  ctx = (DarwinListenerContext *) g_object_new (
      listener_context_get_type (), NULL);
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
  DarwinListenerContext * self = (DarwinListenerContext *) listener;

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
  DarwinListenerContext * self = (DarwinListenerContext *) listener;

  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_LEAVE);

  g_string_append_c (self->harness->result, self->leave_char);

  self->last_return_value = gum_invocation_context_get_return_value (context);
}

static void
listener_context_class_init (DarwinListenerContextClass * klass)
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
listener_context_init (DarwinListenerContext * self)
{
  (void) self;
}
