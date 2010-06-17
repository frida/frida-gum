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

#include "testutil.h"

TEST_LIST_BEGIN (script)
  TEST_ENTRY_SIMPLE (Script, test_replace_string_and_length_arguments)
TEST_LIST_END ()

typedef struct _StringAndLengthArgs StringAndLengthArgs;

struct _StringAndLengthArgs {
  gunichar2 * text;
  guint length;
};

static void
test_replace_string_and_length_arguments (void)
{
  const gchar * script_text =
    "var new_text = \"No, not me!\"\n"
    "ReplaceArgument 0 AddressOf new_text\n"
    "ReplaceArgument 1 LengthOf new_text\n";
  GumScript * script;
  GError * error = NULL;
  GumCpuContext fake_cpu_ctx = { 0, };
  gunichar2 * previous_text;
  guint previous_length;
  StringAndLengthArgs args;
  gchar * new_text;

  script = gum_script_from_string (script_text, &error);
  g_assert (script != NULL);
  g_assert (error == NULL);

  previous_text = g_utf8_to_utf16 ("Hey you", -1, NULL, NULL, NULL);
  previous_length = 7;
  args.text = previous_text;
  args.length = previous_length;

  gum_script_execute (script, &fake_cpu_ctx, &args);

  g_assert_cmphex ((guint64) args.text, !=, (guint64) previous_text);
  g_assert_cmpuint (args.length, !=, previous_length);
  new_text = g_utf16_to_utf8 (args.text, -1, NULL, NULL, NULL);
  g_assert_cmpstr (new_text, ==, "No, not me!");
  g_free (new_text);
  g_assert_cmpuint (args.length, ==, 11);

  g_free (previous_text);

  g_object_unref (script);
}
