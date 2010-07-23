/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

typedef void (* TestCallbackListenerFunc) (gpointer user_data,
    GumInvocationContext * ctx);

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
                                 GumInvocationContext * ctx)
{
  TestCallbackListener * self = TEST_CALLBACK_LISTENER (listener);

  if (self->on_enter != NULL)
    self->on_enter (self->user_data, ctx);
}

static void
test_callback_listener_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * ctx)
{
  TestCallbackListener * self = TEST_CALLBACK_LISTENER (listener);

  if (self->on_leave != NULL)
    self->on_leave (self->user_data, ctx);
}

static gpointer
test_callback_listener_provide_thread_data (GumInvocationListener * listener,
                                            gpointer function_instance_data,
                                            guint thread_id)
{
  return NULL;
}

static void
test_callback_listener_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = test_callback_listener_on_enter;
  iface->on_leave = test_callback_listener_on_leave;
  iface->provide_thread_data = test_callback_listener_provide_thread_data;
}

static void
test_callback_listener_class_init (TestCallbackListenerClass * klass)
{
}

static void
test_callback_listener_init (TestCallbackListener * self)
{
}

static TestCallbackListener *
test_callback_listener_new (void)
{
  return (TestCallbackListener *)
      g_object_new (TEST_TYPE_CALLBACK_LISTENER, NULL);
}
