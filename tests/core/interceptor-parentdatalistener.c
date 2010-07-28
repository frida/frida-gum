/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

typedef struct {
  GObject parent;
  GumInvocationContext a_on_enter_parent_ctx;
  GumInvocationContext a_on_leave_parent_ctx;
  GumInvocationContext c_on_enter_parent_ctx;
  GumInvocationContext c_on_leave_parent_ctx;
} TestParentDataListener;

typedef struct {
  GObjectClass parent_class;
} TestParentDataListenerClass;

#define TEST_TYPE_PARENT_DATA_LISTENER \
    (test_parent_data_listener_get_type ())
#define TEST_PARENT_DATA_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    TEST_TYPE_PARENT_DATA_LISTENER, TestParentDataListener))

static void test_parent_data_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (TestParentDataListener,
                        test_parent_data_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            test_parent_data_listener_iface_init));

static void
fill_invocation_context (GumInvocationContext * context,
                         const GumInvocationContext * src)
{
  if (src != NULL)
    memcpy (context, src, sizeof (GumInvocationContext));
  else
    memset (context, 0, sizeof (GumInvocationContext));
}

static void
test_parent_data_listener_on_enter (GumInvocationListener * listener,
                                    GumInvocationContext * context)
{
  TestParentDataListener * self = TEST_PARENT_DATA_LISTENER (listener);
  GumInvocationContext * parent_context;

  parent_context = gum_invocation_context_get_parent (context);

  if (strcmp ((gchar *) context->instance_data, "a") == 0)
    fill_invocation_context (&self->a_on_enter_parent_ctx, parent_context);
  else if (strcmp ((gchar *) context->instance_data, "c") == 0)
    fill_invocation_context (&self->c_on_enter_parent_ctx, parent_context);
}

static void
test_parent_data_listener_on_leave (GumInvocationListener * listener,
                                    GumInvocationContext * context)
{
  TestParentDataListener * self = TEST_PARENT_DATA_LISTENER (listener);
  GumInvocationContext * parent_context;

  parent_context = gum_invocation_context_get_parent (context);

  if (strcmp ((gchar *) context->instance_data, "a") == 0)
    fill_invocation_context (&self->a_on_leave_parent_ctx, parent_context);
  else if (strcmp ((gchar *) context->instance_data, "c") == 0)
    fill_invocation_context (&self->c_on_leave_parent_ctx, parent_context);
}

static gpointer
test_parent_data_listener_provide_thread_data (GumInvocationListener * listener,
                                               gpointer function_instance_data,
                                               guint thread_id)
{
  if (strcmp ((gchar *) function_instance_data, "a") == 0)
    return "a1";
  else if (strcmp ((gchar *) function_instance_data, "c") == 0)
    return "c1";
  else
    g_assert_not_reached ();

  return NULL;
}

static void
test_parent_data_listener_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = test_parent_data_listener_on_enter;
  iface->on_leave = test_parent_data_listener_on_leave;
  iface->provide_thread_data = test_parent_data_listener_provide_thread_data;
}

static void
test_parent_data_listener_class_init (TestParentDataListenerClass * klass)
{
}

static void
test_parent_data_listener_init (TestParentDataListener * self)
{
}
