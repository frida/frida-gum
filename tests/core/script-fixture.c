/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

#include "testutil.h"

#include <stdio.h>
#include <string.h>
#include <gio/gio.h>
#ifdef G_OS_WIN32
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
# include <tchar.h>
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <errno.h>
# include <fcntl.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
#endif

#define SCRIPT_MESSAGE_TIMEOUT_MSEC 500

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
    g_assert (test_script_fixture_try_pop_message (fixture, 1) == NULL)
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD, ...) \
    test_script_fixture_expect_send_message_with (fixture, PAYLOAD, \
    ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(PAYLOAD, DATA) \
    test_script_fixture_expect_send_message_with_payload_and_data (fixture, \
        PAYLOAD, DATA)
#define EXPECT_ERROR_MESSAGE_WITH(LINE_NUMBER, DESC) \
    test_script_fixture_expect_error_message_with (fixture, LINE_NUMBER, DESC)

#define GUM_PTR_CONST "ptr(\"0x%" G_GSIZE_MODIFIER "x\")"

#ifdef G_OS_WIN32
# define GUM_CLOSE_SOCKET(s) closesocket (s)
#else
# define GUM_CLOSE_SOCKET(s) close (s)
#endif

typedef struct _TestScriptFixture
{
  GumScript * script;
  GMainLoop * loop;
  GMainContext * context;
  GQueue * messages;
} TestScriptFixture;

typedef struct _TestScriptMessageItem
{
  gchar * message;
  gchar * data;
} TestScriptMessageItem;

static TestScriptMessageItem * test_script_fixture_try_pop_message (
    TestScriptFixture * fixture, guint timeout);
static gboolean test_script_fixture_stop_loop (TestScriptFixture * fixture);

static void
test_script_fixture_setup (TestScriptFixture * fixture,
                           gconstpointer data)
{
  fixture->context = g_main_context_ref_thread_default ();
  fixture->loop = g_main_loop_new (fixture->context, FALSE);
  fixture->messages = g_queue_new ();
}

static void
test_script_fixture_teardown (TestScriptFixture * fixture,
                              gconstpointer data)
{
  if (fixture->script != NULL)
    g_object_unref (fixture->script);

  EXPECT_NO_MESSAGES ();
  g_queue_free (fixture->messages);
  g_main_loop_unref (fixture->loop);
  g_main_context_unref (fixture->context);
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

  g_queue_push_tail (self->messages, item);
  g_main_loop_quit (self->loop);
}

static void
test_script_fixture_compile_and_load_script (TestScriptFixture * fixture,
                                             const gchar * source_template,
                                             ...)
{
  va_list args;
  gchar * source;
  GError * err = NULL;

  if (fixture->script != NULL)
  {
    gum_script_unload_sync (fixture->script, NULL);
    g_object_unref (fixture->script);
    fixture->script = NULL;
  }

  va_start (args, source_template);
  source = g_strdup_vprintf (source_template, args);
  va_end (args);

  fixture->script =
      gum_script_from_string_sync ("testcase", source, NULL, &err);
  g_assert (fixture->script != NULL);
  g_assert (err == NULL);

  g_free (source);

  gum_script_set_message_handler (fixture->script,
      test_script_fixture_store_message, fixture, NULL);

  gum_script_load_sync (fixture->script, NULL);
}

static TestScriptMessageItem *
test_script_fixture_try_pop_message (TestScriptFixture * fixture,
                                     guint timeout)
{
  if (g_queue_is_empty (fixture->messages))
  {
    GSource * source;

    source = g_timeout_source_new (timeout);
    g_source_set_callback (source, (GSourceFunc) test_script_fixture_stop_loop,
        fixture, NULL);
    g_source_attach (source, fixture->context);

    g_main_loop_run (fixture->loop);

    g_source_destroy (source);
    g_source_unref (source);
  }

  return g_queue_pop_head (fixture->messages);
}

static gboolean
test_script_fixture_stop_loop (TestScriptFixture * fixture)
{
  g_main_loop_quit (fixture->loop);

  return FALSE;
}

static TestScriptMessageItem *
test_script_fixture_pop_message (TestScriptFixture * fixture)
{
  TestScriptMessageItem * item;

  item = test_script_fixture_try_pop_message (fixture,
      SCRIPT_MESSAGE_TIMEOUT_MSEC);
  g_assert (item != NULL);

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

static gint gum_toupper (gchar * str, gint limit);
static gint gum_sum (gint count, ...);

#ifndef HAVE_ANDROID
static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);
#endif

static gpointer invoke_target_function_int_worker (gpointer data);

static void on_message (GumScript * script, const gchar * message,
    const guint8 * data, gint data_length, gpointer user_data);

static int target_function_int (int arg);
static const gchar * target_function_string (const gchar * arg);
static int target_function_nested_a (int arg);
static int target_function_nested_b (int arg);
static int target_function_nested_c (int arg);

gint gum_script_dummy_global_to_trick_optimizer = 0;
