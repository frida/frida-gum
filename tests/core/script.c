/*
 * Copyright (C) 2010-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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
  SCRIPT_TESTENTRY (int_argument_can_be_sent)
  SCRIPT_TESTENTRY (return_value_can_be_sent)
TEST_LIST_END ()

static int target_function_int (int arg);

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

SCRIPT_TESTCASE (int_argument_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(0x%x, {"
      "  onEnter: function(args) {"
      "    send(args[0]);"
      "  }"
      "});", target_function_int);

  target_function_int (42);

  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (return_value_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(0x%x, {"
      "  onLeave: function(retval) {"
      "    send(retval);"
      "  }"
      "});", target_function_int);

  target_function_int (7);

  EXPECT_SEND_MESSAGE_WITH ("315");
}

GUM_NOINLINE static int
target_function_int (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  return result;
}