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

#include "gumscript.h"

#include "testutil.h"

#include <string.h>
#include <gio/gio.h>
#ifdef G_OS_WIN32
# define VC_EXTRALEAN
# include <stdio.h>
# include <tchar.h>
# include <windows.h>
#else
# include <fcntl.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
#endif

#define SCRIPT_MESSAGE_TIMEOUT_USEC (500000)

#define SCRIPT_TESTCASE(NAME) \
    void test_script_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define SCRIPT_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Script", test_script, NAME, \
        TestScriptFixture)

#define COMPILE_AND_LOAD_SCRIPT(SOURCE, ...) \
    test_script_fixture_compile_and_load_script (fixture, SOURCE, \
    ## __VA_ARGS__)
#define POST_MESSAGE(MSG) \
    gum_script_post_message (fixture->script, MSG)
#define EXPECT_NO_MESSAGES() \
    g_assert_cmpuint (g_async_queue_length (fixture->messages), ==, 0)
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD, ...) \
    test_script_fixture_expect_send_message_with (fixture, PAYLOAD, \
    ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(PAYLOAD, DATA) \
    test_script_fixture_expect_send_message_with_payload_and_data (fixture, \
        PAYLOAD, DATA)
#define EXPECT_ERROR_MESSAGE_WITH(LINE_NUMBER, DESC) \
    test_script_fixture_expect_error_message_with (fixture, LINE_NUMBER, DESC)

#define GUM_PTR_FORMAT "0x%" G_GSIZE_MODIFIER "x"

typedef struct _TestScriptFixture
{
  GumScript * script;
  GAsyncQueue * messages;
} TestScriptFixture;

typedef struct _TestScriptMessageItem
{
  gchar * message;
  gchar * data;
} TestScriptMessageItem;

static void
test_script_fixture_setup (TestScriptFixture * fixture,
                           gconstpointer data)
{
  fixture->messages = g_async_queue_new ();
}

static void
test_script_fixture_teardown (TestScriptFixture * fixture,
                              gconstpointer data)
{
  if (fixture->script != NULL)
    g_object_unref (fixture->script);

  EXPECT_NO_MESSAGES ();
  g_async_queue_unref (fixture->messages);
}

static void
test_script_message_item_free (TestScriptMessageItem * item)
{
  g_free (item->message);
  g_free (item->data);
  g_slice_free (TestScriptMessageItem, item);
}

static void
test_script_fixture_store_message (GumScript * script,
                                   const gchar * message,
                                   const guint8 * data,
                                   gint data_length,
                                   gpointer user_data)
{
  TestScriptFixture * self = (TestScriptFixture *) user_data;
  TestScriptMessageItem * item;

  item = g_slice_new (TestScriptMessageItem);
  item->message = g_strdup (message);
  if (data != NULL)
  {
    GString * s;
    gint i;

    s = g_string_sized_new (3 * data_length);
    for (i = 0; i != data_length; i++)
    {
      if (i != 0)
        g_string_append_c (s, ' ');
      g_string_append_printf (s, "%02x", (int) data[i]);
    }

    item->data = g_string_free (s, FALSE);
  }
  else
  {
    item->data = NULL;
  }

  g_async_queue_push (self->messages, item);
}

static void
test_script_fixture_compile_and_load_script (TestScriptFixture * fixture,
                                             const gchar * source_template,
                                             ...)
{
  va_list args;
  gchar * source;
  GError * err = NULL;

  va_start (args, source_template);
  source = g_strdup_vprintf (source_template, args);
  va_end (args);

  fixture->script = gum_script_from_string (source, &err);
  g_assert (fixture->script != NULL);
  g_assert (err == NULL);

  g_free (source);

  gum_script_set_message_handler (fixture->script,
      test_script_fixture_store_message, fixture, NULL);
  gum_script_load (fixture->script);
}

static TestScriptMessageItem *
test_script_fixture_pop_message (TestScriptFixture * fixture)
{
  GTimeVal end_time;
  TestScriptMessageItem * item;

  g_get_current_time (&end_time);
  g_time_val_add (&end_time, SCRIPT_MESSAGE_TIMEOUT_USEC);
  item = (TestScriptMessageItem *) g_async_queue_timed_pop (fixture->messages,
      &end_time);

  return item;
}

static void
test_script_fixture_expect_send_message_with (TestScriptFixture * fixture,
                                              const gchar * payload_template,
                                              ...)
{
  va_list args;
  gchar * payload;
  TestScriptMessageItem * item;
  gchar * expected_message;

  va_start (args, payload_template);
  payload = g_strdup_vprintf (payload_template, args);
  va_end (args);

  item = test_script_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  test_script_message_item_free (item);
  g_free (expected_message);

  g_free (payload);
}

static void
test_script_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture,
    const gchar * payload,
    const gchar * data)
{
  TestScriptMessageItem * item;
  gchar * expected_message;

  item = test_script_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  g_assert (item->data != NULL);
  g_assert_cmpstr (item->data, ==, data);
  test_script_message_item_free (item);
  g_free (expected_message);
}

static void
test_script_fixture_expect_error_message_with (TestScriptFixture * fixture,
                                               gint line_number,
                                               const gchar * description)
{
  TestScriptMessageItem * item;
  gchar * expected_message;

  item = test_script_fixture_pop_message (fixture);
  expected_message = g_strdup_printf ("{"
          "\"type\":\"error\","
          "\"lineNumber\":%d,"
          "\"description\":\"%s\""
      "}",
      line_number, description);
  g_assert_cmpstr (item->message, ==, expected_message);
  test_script_message_item_free (item);
  g_free (expected_message);
}

static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);

static gpointer invoke_target_function_int_worker (gpointer data);

static int target_function_int (int arg);
static const gchar * target_function_string (const gchar * arg);

static gint gum_dummy_global_to_trick_optimizer = 0;
