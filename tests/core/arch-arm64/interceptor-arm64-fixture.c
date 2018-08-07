/*
 * Copyright (C) 2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "testutil.h"

#include <string.h>

#define INTERCEPTOR_TESTCASE(NAME) \
    void interceptor_ ## NAME ( \
        InterceptorFixture * fixture, gconstpointer data)
#define INTERCEPTOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Interceptor/Arm64", \
        interceptor, NAME, InterceptorFixture)

typedef struct _InterceptorFixture        InterceptorFixture;
typedef struct _Arm64ListenerContext      Arm64ListenerContext;
typedef struct _Arm64ListenerContextClass Arm64ListenerContextClass;

struct _Arm64ListenerContext
{
  GObject parent;

  InterceptorFixture * harness;
  gchar enter_char;
  gchar leave_char;
};

struct _Arm64ListenerContextClass
{
  GObjectClass parent_class;
};

struct _InterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  Arm64ListenerContext * listener_context[2];
};

static void arm64_listener_context_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (Arm64ListenerContext,
                        arm64_listener_context,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            arm64_listener_context_iface_init))

static void
interceptor_fixture_setup (InterceptorFixture * fixture,
                           gconstpointer data)
{
  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);
  memset (&fixture->listener_context, 0, sizeof (fixture->listener_context));
}

static void
interceptor_fixture_teardown (InterceptorFixture * fixture,
                              gconstpointer data)
{
  guint i;

  for (i = 0; i < G_N_ELEMENTS (fixture->listener_context); i++)
  {
    Arm64ListenerContext * ctx = fixture->listener_context[i];

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

static GumAttachReturn
interceptor_fixture_try_attaching_listener (InterceptorFixture * h,
                                            guint listener_index,
                                            gpointer test_func,
                                            gchar enter_char,
                                            gchar leave_char)
{
  GumAttachReturn result;
  Arm64ListenerContext * ctx;

  g_clear_object (&h->listener_context[listener_index]);

  ctx = g_object_new (arm64_listener_context_get_type (), NULL);
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

static void
interceptor_fixture_attach_listener (InterceptorFixture * h,
                                     guint listener_index,
                                     gpointer test_func,
                                     gchar enter_char,
                                     gchar leave_char)
{
  g_assert_cmpint (interceptor_fixture_try_attaching_listener (h,
      listener_index, test_func, enter_char, leave_char), ==,
      GUM_ATTACH_OK);
}

static void
interceptor_fixture_detach_listener (InterceptorFixture * h,
                                     guint listener_index)
{
  gum_interceptor_detach_listener (h->interceptor,
    GUM_INVOCATION_LISTENER (h->listener_context[listener_index]));
}

static void
arm64_listener_context_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  Arm64ListenerContext * self = (Arm64ListenerContext *) listener;

  g_string_append_c (self->harness->result, self->enter_char);
}

static void
arm64_listener_context_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  Arm64ListenerContext * self = (Arm64ListenerContext *) listener;

  g_string_append_c (self->harness->result, self->leave_char);
}

static void
arm64_listener_context_class_init (Arm64ListenerContextClass * klass)
{
}

static void
arm64_listener_context_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = arm64_listener_context_on_enter;
  iface->on_leave = arm64_listener_context_on_leave;
}

static void
arm64_listener_context_init (Arm64ListenerContext * self)
{
}
