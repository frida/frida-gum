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

#define SCRIPT_TESTCASE(NAME) \
    void test_script_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define SCRIPT_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Script", test_script, NAME, \
        TestScriptFixture)

#define COMPILE_AND_LOAD_SCRIPT(SOURCE, FUNC) \
    test_script_fixture_compile_and_load_script (fixture, SOURCE, FUNC)
#define EXPECT_NO_MESSAGES() \
    g_assert_cmpuint (g_queue_get_length (fixture->messages), ==, 0)
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD) \
    test_script_fixture_expect_send_message_with (fixture, PAYLOAD)

typedef struct _TestScriptFixture
{
  GumScript * script;
  GQueue * messages;
} TestScriptFixture;

static void
test_script_fixture_setup (TestScriptFixture * fixture,
                           gconstpointer data)
{
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
}

static void
test_script_fixture_store_message (GumScript * script,
                                   const gchar * msg,
                                   gpointer user_data)
{
  TestScriptFixture * self = (TestScriptFixture *) user_data;

  g_queue_push_tail (self->messages, g_strdup (msg));
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

  EXPECT_NO_MESSAGES ();
}

static void
test_script_fixture_expect_send_message_with (TestScriptFixture * fixture,
                                              const gchar * payload)
{
  gchar * actual_message, * expected_message;

  g_assert_cmpuint (g_queue_get_length (fixture->messages), >=, 1);

  actual_message = (gchar *) g_queue_pop_head (fixture->messages);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);

  g_assert_cmpstr (actual_message, ==, expected_message);

  g_free (expected_message);
  g_free (actual_message);
}