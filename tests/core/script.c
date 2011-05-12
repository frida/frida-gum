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

#include "script-fixture.c"

TEST_LIST_BEGIN (script)
  SCRIPT_TESTENTRY (invalid_script_should_return_null)
  SCRIPT_TESTENTRY (json_can_be_sent)
TEST_LIST_END ()

static void store_message (GumScript * script, const gchar * msg,
    gpointer user_data);

SCRIPT_TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert (gum_script_from_string ("'", NULL) == NULL);

  g_assert (gum_script_from_string ("'", &err) == NULL);
  g_assert (err != NULL);
  g_assert_cmpstr (err->message, ==,
      "Script(line 1): SyntaxError: Unexpected token ILLEGAL");
}

SCRIPT_TESTCASE (json_can_be_sent)
{
  GumScript * script;
  GError * err = NULL;
  gchar * msg = NULL;

  script = gum_script_from_string (
    "var message = {\n"
    "  type: 'hello'\n"
    "};\n"
    "send(JSON.stringify(message));", &err);
  g_assert (script != NULL);
  g_assert (err == NULL);

  gum_script_set_message_handler (script, store_message, &msg, NULL);
  gum_script_execute (script, &fixture->invocation_context);
  g_assert (msg != NULL);
  g_assert_cmpstr (msg, ==, "{\"type\":\"hello\"}");
  g_free (msg);

  g_object_unref (script);
}

static void
store_message (GumScript * script,
               const gchar * msg,
               gpointer user_data)
{
  gchar ** testcase_msg_ptr = (gchar **) user_data;

  g_assert (*testcase_msg_ptr == NULL);
  *testcase_msg_ptr = g_strdup (msg);
}