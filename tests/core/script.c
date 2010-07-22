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

#define VC_EXTRALEAN
#include <windows.h>

#define SCRIPT_TESTCASE(NAME) \
    void test_script_ ## NAME (void)
#define SCRIPT_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE (Script, test_script, NAME)

TEST_LIST_BEGIN (script)
  SCRIPT_TESTENTRY (replace_string_and_length_arguments)
  SCRIPT_TESTENTRY (send_string_from_argument)
TEST_LIST_END ()

typedef struct _StringAndLengthArgs StringAndLengthArgs;
typedef struct _StringsAndLengthArgs StringsAndLengthArgs;

struct _StringAndLengthArgs {
  gunichar2 * text;
  guint length;
};

struct _StringsAndLengthArgs {
  gchar * text_ansi;
  gunichar2 * text_wide;
  guint length;
};

static void store_message (GumScript * script, GVariant * msg,
    gpointer user_data);

static gchar * ansi_string_from_utf8 (const gchar * str_utf8);

static GumCpuContext fake_cpu_ctx = { 0, };

SCRIPT_TESTCASE (replace_string_and_length_arguments)
{
  const gchar * script_text =
    "var new_text = \"No, not me!\"\n"
    "ReplaceArgument 0 AddressOf new_text\n"
    "ReplaceArgument 1 LengthOf new_text\n";
  GumScript * script;
  GError * error = NULL;
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

SCRIPT_TESTCASE (send_string_from_argument)
{
  const gchar * script_text =
    "SendAnsiStringFromArgument 0\n"
    "SendWideStringFromArgument 1\n"
    "SendInt32FromArgument 2\n";
  GumScript * script;
  GError * error = NULL;
  StringsAndLengthArgs args;
  GVariant * msg = NULL;
  gchar * msg_str_ansi, * msg_str_wide;
  gint32 msg_int;

  script = gum_script_from_string (script_text, &error);
  g_assert (script != NULL);
  g_assert (error == NULL);
  args.text_ansi = ansi_string_from_utf8 ("ÆØÅæøå");
  args.text_wide = g_utf8_to_utf16 ("ÆØÅæøå", -1, NULL, NULL, NULL);
  args.length = 42;

  gum_script_set_message_handler (script, store_message, &msg, NULL);
  gum_script_execute (script, &fake_cpu_ctx, &args);
  g_assert (msg != NULL);
  g_assert (g_variant_is_of_type (msg, G_VARIANT_TYPE ("(ssi)")));
  g_variant_get (msg, "(ssi)", &msg_str_ansi, &msg_str_wide, &msg_int);
  g_assert_cmpstr (msg_str_ansi, ==, "ÆØÅæøå");
  g_assert_cmpstr (msg_str_wide, ==, "ÆØÅæøå");
  g_assert_cmpint (msg_int, ==, 42);

  g_variant_unref (msg);

  g_free (args.text_wide);
  g_free (args.text_ansi);
  g_object_unref (script);
}

static void
store_message (GumScript * script,
               GVariant * msg,
               gpointer user_data)
{
  GVariant ** testcase_msg_ptr = (GVariant **) user_data;

  g_assert (*testcase_msg_ptr == NULL);
  *testcase_msg_ptr = msg;
}

static gchar *
ansi_string_from_utf8 (const gchar * str_utf8)
{
  glong len;
  gunichar2 * str_utf16;
  gchar * str_ansi;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, &len, NULL);
  str_ansi = (gchar *) g_malloc0 (len * 2);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1, str_ansi, len * 2,
      NULL, NULL);
  g_free (str_utf16);

  return str_ansi;
}
