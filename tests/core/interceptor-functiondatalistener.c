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
  guint on_enter_call_count;
  guint on_leave_call_count;
  guint provide_thread_data_call_count;
  GumInvocationContext last_on_enter_ctx;
  GumInvocationContext last_on_leave_ctx;
  GSList * a_threads_seen;
  guint a_thread_index;
  GSList * b_threads_seen;
  guint b_thread_index;
  GSList * provided_thread_data;
} TestFunctionDataListener;

typedef struct {
  GObjectClass parent_class;
} TestFunctionDataListenerClass;

#define TEST_TYPE_FUNCTION_DATA_LISTENER \
    (test_function_data_listener_get_type ())
#define TEST_FUNCTION_DATA_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    TEST_TYPE_FUNCTION_DATA_LISTENER, TestFunctionDataListener))

static void test_function_data_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void test_function_data_listener_finalize (GObject * object);

G_DEFINE_TYPE_EXTENDED (TestFunctionDataListener,
                        test_function_data_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            test_function_data_listener_iface_init));

static void
test_function_data_listener_on_enter (GumInvocationListener * listener,
                                      GumInvocationContext * ctx)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);

  self->on_enter_call_count++;
  self->last_on_enter_ctx = *ctx;
}

static void
test_function_data_listener_on_leave (GumInvocationListener * listener,
                                      GumInvocationContext * ctx)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);

  self->on_leave_call_count++;
  self->last_on_leave_ctx = *ctx;
}

static gpointer
test_context_provide_thread_data (GumInvocationListener * listener,
                                  gpointer function_instance_data,
                                  guint thread_id)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (listener);
  GSList ** threads_seen = NULL;
  guint * thread_index = 0;
  GThread * cur_thread;
  gchar * thread_data;

  self->provide_thread_data_call_count++;

  if (strcmp ((gchar *) function_instance_data, "a") == 0)
  {
    threads_seen = &self->a_threads_seen;
    thread_index = &self->a_thread_index;
  }
  else if (strcmp ((gchar *) function_instance_data, "b") == 0)
  {
    threads_seen = &self->b_threads_seen;
    thread_index = &self->b_thread_index;
  }
  else
    g_assert_not_reached ();

  cur_thread = g_thread_self ();
  if (g_slist_find (*threads_seen, cur_thread) == NULL)
  {
    *threads_seen = g_slist_prepend (*threads_seen, cur_thread);
    (*thread_index)++;
  }

  thread_data =
      g_strdup_printf ("%s%d", (gchar *) function_instance_data, *thread_index);
  self->provided_thread_data = g_slist_prepend (self->provided_thread_data,
      thread_data);
  return thread_data;
}

static void
test_function_data_listener_iface_init (gpointer g_iface,
                                        gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = test_function_data_listener_on_enter;
  iface->on_leave = test_function_data_listener_on_leave;
  iface->provide_thread_data = test_context_provide_thread_data;
}

static void
test_function_data_listener_class_init (TestFunctionDataListenerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = test_function_data_listener_finalize;
}

static void
test_function_data_listener_init (TestFunctionDataListener * self)
{
}

static void
test_function_data_listener_finalize (GObject * object)
{
  TestFunctionDataListener * self = TEST_FUNCTION_DATA_LISTENER (object);

  while (self->provided_thread_data != NULL)
  {
    gchar * entry = (gchar *) self->provided_thread_data->data;
    self->provided_thread_data = g_slist_remove (self->provided_thread_data,
        entry);
    g_free (entry);
  }

  G_OBJECT_CLASS (test_function_data_listener_parent_class)->finalize (object);
}

static void
test_function_data_listener_reset (TestFunctionDataListener * self)
{
  self->on_enter_call_count = 0;
  self->on_leave_call_count = 0;
  self->provide_thread_data_call_count = 0;
  memset (&self->last_on_enter_ctx, 0, sizeof (GumInvocationContext));
  memset (&self->last_on_leave_ctx, 0, sizeof (GumInvocationContext));
}
