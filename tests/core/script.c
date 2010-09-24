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
  SCRIPT_TESTENTRY (replace_string_and_length_arguments)
  SCRIPT_TESTENTRY (send_string_from_argument)
  SCRIPT_TESTENTRY (send_narrow_format_string_from_argument)
  SCRIPT_TESTENTRY (send_wide_format_string_from_argument)
TEST_LIST_END ()

typedef struct _StringAndLengthArgs StringAndLengthArgs;
typedef struct _StringsAndLengthArgs StringsAndLengthArgs;
typedef struct _NarrowFormatStringArgs NarrowFormatStringArgs;
typedef struct _WideFormatStringArgs WideFormatStringArgs;

struct _StringAndLengthArgs {
  gunichar2 * text;
  guint length;
};

struct _StringsAndLengthArgs {
  gchar * text_narrow;
  gunichar2 * text_wide;
  guint length;
};

struct _NarrowFormatStringArgs {
  gchar * format;
  gchar * name;
  guint age;
};

struct _WideFormatStringArgs {
  gunichar2 * format;
  gunichar2 * name;
  guint age;
};

static void store_message (GumScript * script, GVariant * msg,
    gpointer user_data);

static gchar * narrow_string_from_utf8 (const gchar * str_utf8);

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
  fixture->argument_list = &args;

  gum_script_execute (script, &fixture->invocation_context);

  g_assert_cmphex (GPOINTER_TO_SIZE (args.text), !=,
      GPOINTER_TO_SIZE (previous_text));
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
    "SendNarrowStringFromArgument 0\n"
    "SendWideStringFromArgument 1\n"
    "SendInt32FromArgument 2\n";
  GumScript * script;
  GError * error = NULL;
  StringsAndLengthArgs args;
  GVariant * msg = NULL;
  gchar * msg_str_narrow, * msg_str_wide;
  gint32 msg_int;

  script = gum_script_from_string (script_text, &error);
  g_assert (script != NULL);
  g_assert (error == NULL);
  args.text_narrow = narrow_string_from_utf8 ("ÆØÅæøå");
  args.text_wide = g_utf8_to_utf16 ("ÆØÅæøå", -1, NULL, NULL, NULL);
  args.length = 42;
  fixture->argument_list = &args;

  gum_script_set_message_handler (script, store_message, &msg, NULL);
  gum_script_execute (script, &fixture->invocation_context);
  g_assert (msg != NULL);
  g_assert (g_variant_is_of_type (msg, G_VARIANT_TYPE ("(ssi)")));
  g_variant_get (msg, "(ssi)", &msg_str_narrow, &msg_str_wide, &msg_int);
  g_assert_cmpstr (msg_str_narrow, ==, "ÆØÅæøå");
  g_assert_cmpstr (msg_str_wide, ==, "ÆØÅæøå");
  g_assert_cmpint (msg_int, ==, 42);

  g_variant_unref (msg);

  g_free (args.text_wide);
  g_free (args.text_narrow);
  g_object_unref (script);
}

SCRIPT_TESTCASE (send_narrow_format_string_from_argument)
{
  const gchar * script_text = "SendNarrowFormatStringFromArgument 0";
  GumScript * script;
  GError * error = NULL;
  NarrowFormatStringArgs args;
  GVariant * msg = NULL;
  gchar * msg_str;

  script = gum_script_from_string (script_text, &error);
  g_assert (script != NULL);
  g_assert (error == NULL);
  args.format =
    narrow_string_from_utf8 ("My name is %s and I æm %%%03d");
  args.name = narrow_string_from_utf8 ("Bøggvald");
  args.age = 7;
  fixture->argument_list = &args;

  gum_script_set_message_handler (script, store_message, &msg, NULL);
  gum_script_execute (script, &fixture->invocation_context);
  g_assert (msg != NULL);
  g_assert (g_variant_is_of_type (msg, G_VARIANT_TYPE ("(s)")));
  g_variant_get (msg, "(s)", &msg_str);
  g_assert_cmpstr (msg_str, ==, "My name is Bøggvald and I æm %007");

  g_variant_unref (msg);

  g_free (args.name);
  g_free (args.format);
  g_object_unref (script);
}

SCRIPT_TESTCASE (send_wide_format_string_from_argument)
{
  const gchar * script_text = "SendWideFormatStringFromArgument 0";
  GumScript * script;
  GError * error = NULL;
  WideFormatStringArgs args;
  GVariant * msg = NULL;
  gchar * msg_str;

  script = gum_script_from_string (script_text, &error);
  g_assert (script != NULL);
  g_assert (error == NULL);
  args.format =
      g_utf8_to_utf16 ("My name is %s and I æm %%%03d", -1, NULL, NULL, NULL);
  args.name =
      g_utf8_to_utf16 ("Bøggvald", -1, NULL, NULL, NULL);
  args.age = 7;
  fixture->argument_list = &args;

  gum_script_set_message_handler (script, store_message, &msg, NULL);
  gum_script_execute (script, &fixture->invocation_context);
  g_assert (msg != NULL);
  g_assert (g_variant_is_of_type (msg, G_VARIANT_TYPE ("(s)")));
  g_variant_get (msg, "(s)", &msg_str);
  g_assert_cmpstr (msg_str, ==, "My name is Bøggvald and I æm %007");

  g_variant_unref (msg);

  g_free (args.name);
  g_free (args.format);
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
narrow_string_from_utf8 (const gchar * str_utf8)
{
#ifdef G_OS_WIN32
  glong len;
  gunichar2 * str_utf16;
  gchar * str_narrow;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, &len, NULL);
  str_narrow = (gchar *) g_malloc0 (len * 2);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1, str_narrow, len * 2,
      NULL, NULL);
  g_free (str_utf16);

  return str_narrow;
#else
  return g_strdup (str_utf8);
#endif
}
