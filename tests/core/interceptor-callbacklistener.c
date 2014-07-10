/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

typedef void (* TestCallbackListenerFunc) (gpointer user_data,
    GumInvocationContext * context);

typedef struct {
  GObject parent;

  TestCallbackListenerFunc on_enter;
  TestCallbackListenerFunc on_leave;
  gpointer user_data;
} TestCallbackListener;

typedef struct {
  GObjectClass parent_class;
} TestCallbackListenerClass;

#define TEST_TYPE_CALLBACK_LISTENER \
    (test_callback_listener_get_type ())
#define TEST_CALLBACK_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
    TEST_TYPE_CALLBACK_LISTENER, TestCallbackListener))

static void test_callback_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (TestCallbackListener,
                        test_callback_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            test_callback_listener_iface_init));

static void
test_callback_listener_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  TestCallbackListener * self = TEST_CALLBACK_LISTENER (listener);

  if (self->on_enter != NULL)
    self->on_enter (self->user_data, context);
}

static void
test_callback_listener_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * context)
{
  TestCallbackListener * self = TEST_CALLBACK_LISTENER (listener);

  if (self->on_leave != NULL)
    self->on_leave (self->user_data, context);
}

static void
test_callback_listener_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = test_callback_listener_on_enter;
  iface->on_leave = test_callback_listener_on_leave;
}

static void
test_callback_listener_class_init (TestCallbackListenerClass * klass)
{
  (void) klass;
}

static void
test_callback_listener_init (TestCallbackListener * self)
{
  (void) self;
}

static TestCallbackListener *
test_callback_listener_new (void)
{
  return (TestCallbackListener *)
      g_object_new (TEST_TYPE_CALLBACK_LISTENER, NULL);
}
