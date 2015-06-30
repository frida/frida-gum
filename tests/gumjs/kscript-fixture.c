/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

#include "testutil.h"

#include <stdio.h>

#define ANY_LINE_NUMBER -1
#define KSCRIPT_MESSAGE_TIMEOUT_MSEC 500

#ifndef KSCRIPT_SUITE
# define KSCRIPT_SUITE ""
#endif
#define KSCRIPT_TESTCASE(NAME) \
    void test_kscript_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define KSCRIPT_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("GumJS/KScript" KSCRIPT_SUITE, test_kscript, \
        NAME, TestScriptFixture)

#define COMPILE_AND_LOAD_SCRIPT(SOURCE, ...) \
    test_kscript_fixture_compile_and_load_kscript (fixture, SOURCE, \
    ## __VA_ARGS__)
#define POST_MESSAGE(MSG) \
    gum_script_post_message (fixture->kscript, MSG)
#define EXPECT_NO_MESSAGES() \
    g_assert (test_kscript_fixture_try_pop_message (fixture, 1) == NULL)
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD, ...) \
    test_kscript_fixture_expect_send_message_with (fixture, PAYLOAD, \
    ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(PAYLOAD, DATA) \
    test_kscript_fixture_expect_send_message_with_payload_and_data (fixture, \
        PAYLOAD, DATA)
#define EXPECT_ERROR_MESSAGE_WITH(LINE_NUMBER, DESC) \
    test_kscript_fixture_expect_error_message_with (fixture, LINE_NUMBER, DESC)

#define GUM_PTR_CONST "ptr(\"0x%" G_GSIZE_MODIFIER "x\")"

typedef struct _TestScriptFixture
{
  GumScript * kscript;
  GMainLoop * loop;
  GMainContext * context;
  GQueue * messages;
} TestScriptFixture;

typedef struct _TestScriptMessageItem
{
  gchar * message;
  gchar * data;
} TestScriptMessageItem;

static void test_kscript_message_item_free (TestScriptMessageItem * item);
static TestScriptMessageItem * test_kscript_fixture_try_pop_message (
    TestScriptFixture * fixture, guint timeout);
static gboolean test_kscript_fixture_stop_loop (TestScriptFixture * fixture);
static void test_kscript_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture, const gchar * payload, const gchar * data);
static void test_kscript_fixture_expect_error_message_with (
    TestScriptFixture * fixture, gint line_number, const gchar * description);

static void
test_kscript_fixture_setup (TestScriptFixture * fixture,
                            gconstpointer data)
{
  (void) test_kscript_fixture_expect_send_message_with_payload_and_data;
  (void) test_kscript_fixture_expect_error_message_with;

  fixture->context = g_main_context_ref_thread_default ();
  fixture->loop = g_main_loop_new (fixture->context, FALSE);
  fixture->messages = g_queue_new ();
}

static void
test_kscript_fixture_teardown (TestScriptFixture * fixture,
                               gconstpointer data)
{
  TestScriptMessageItem * item;

  if (fixture->kscript != NULL)
  {
    gum_script_unload_sync (fixture->kscript, NULL);
    g_object_unref (fixture->kscript);
  }

  while (g_main_context_pending (fixture->context))
    g_main_context_iteration (fixture->context, FALSE);

  while ((item = test_kscript_fixture_try_pop_message (fixture, 1)) != NULL)
  {
    test_kscript_message_item_free (item);
  }
  g_queue_free (fixture->messages);

  g_main_loop_unref (fixture->loop);
  g_main_context_unref (fixture->context);
}

static void
test_kscript_message_item_free (TestScriptMessageItem * item)
{
  g_free (item->message);
  g_free (item->data);
  g_slice_free (TestScriptMessageItem, item);
}

static void
test_kscript_fixture_store_message (GumScript * kscript,
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
test_kscript_fixture_compile_and_load_kscript (TestScriptFixture * fixture,
                                               const gchar * source_template,
                                               ...)
{
  va_list args;
  gchar * source;
  GError * err = NULL;

  if (fixture->kscript != NULL)
  {
    gum_script_unload_sync (fixture->kscript, NULL);
    g_object_unref (fixture->kscript);
    fixture->kscript = NULL;
  }

  va_start (args, source_template);
  source = g_strdup_vprintf (source_template, args);
  va_end (args);

  fixture->kscript = gum_script_from_string_sync ("testcase", source,
      GUM_SCRIPT_FLAVOR_KERNEL, NULL, &err);
  g_assert (fixture->kscript != NULL);
  g_assert (err == NULL);

  g_free (source);

  gum_script_set_message_handler (fixture->kscript,
      test_kscript_fixture_store_message, fixture, NULL);

  gum_script_load_sync (fixture->kscript, NULL);
}

static TestScriptMessageItem *
test_kscript_fixture_try_pop_message (TestScriptFixture * fixture,
                                      guint timeout)
{
  if (g_queue_is_empty (fixture->messages))
  {
    GSource * source;

    source = g_timeout_source_new (timeout);
    g_source_set_callback (source, (GSourceFunc) test_kscript_fixture_stop_loop,
        fixture, NULL);
    g_source_attach (source, fixture->context);

    g_main_loop_run (fixture->loop);

    g_source_destroy (source);
    g_source_unref (source);
  }

  return g_queue_pop_head (fixture->messages);
}

static gboolean
test_kscript_fixture_stop_loop (TestScriptFixture * fixture)
{
  g_main_loop_quit (fixture->loop);

  return FALSE;
}

static TestScriptMessageItem *
test_kscript_fixture_pop_message (TestScriptFixture * fixture)
{
  TestScriptMessageItem * item;

  item = test_kscript_fixture_try_pop_message (fixture,
      KSCRIPT_MESSAGE_TIMEOUT_MSEC);
  g_assert (item != NULL);

  return item;
}

static void
test_kscript_fixture_expect_send_message_with (TestScriptFixture * fixture,
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

  item = test_kscript_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  test_kscript_message_item_free (item);
  g_free (expected_message);

  g_free (payload);
}

static void
test_kscript_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture,
    const gchar * payload,
    const gchar * data)
{
  TestScriptMessageItem * item;
  gchar * expected_message;

  item = test_kscript_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  if (data != NULL)
  {
    g_assert (item->data != NULL);
    g_assert_cmpstr (item->data, ==, data);
  }
  else
  {
    g_assert (item->data == NULL);
  }
  test_kscript_message_item_free (item);
  g_free (expected_message);
}

static void
test_kscript_fixture_expect_error_message_with (TestScriptFixture * fixture,
                                                gint line_number,
                                                const gchar * description)
{
  TestScriptMessageItem * item;
  gchar actual_file_name[64];
  gint actual_line_number;
  gchar actual_description[512];

  item = test_kscript_fixture_pop_message (fixture);
  sscanf (item->message, "{"
          "\"type\":\"error\","
          "\"fileName\":\"%[^\"]\","
          "\"lineNumber\":%d,"
          "\"description\":\"%[^\"]\""
      "}",
      actual_file_name, &actual_line_number, actual_description);
  if (line_number != ANY_LINE_NUMBER)
    g_assert_cmpint (actual_line_number, ==, line_number);
  g_assert_cmpstr (actual_description, ==, description);
  test_kscript_message_item_free (item);
}

