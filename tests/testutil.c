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

#include "testutil.h"

#include <stdlib.h>
#include <string.h>

#define TESTUTIL_TESTCASE(NAME) \
    void test_testutil_ ## NAME (void)
#define TESTUTIL_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("TestUtil", test_testutil, NAME)

TEST_LIST_BEGIN (testutil)
  TESTUTIL_TESTENTRY (line_diff)
  TESTUTIL_TESTENTRY (binary_diff)
  TESTUTIL_TESTENTRY (text_diff)
  TESTUTIL_TESTENTRY (xml_pretty_split)
  TESTUTIL_TESTENTRY (xml_multiline_diff_same_size)
TEST_LIST_END ()

static gchar * byte_array_to_hex_string (const guint8 * bytes, guint length);
static gchar * byte_array_to_bin_string (const guint8 * bytes, guint length);
static gchar * prettify_xml (const gchar * input_xml);
static void on_start_element (GMarkupParseContext * context,
    const gchar * element_name, const gchar ** attribute_names,
    const gchar ** attribute_values, gpointer user_data,
    GError ** error);
static void on_end_element (GMarkupParseContext * context,
    const gchar * element_name, gpointer user_data, GError ** error);
static void on_text (GMarkupParseContext * context, const gchar * text,
    gsize text_len, gpointer user_data, GError ** error);
static gchar * diff_line (const gchar * expected_line,
    const gchar * actual_line);
static void append_indent (GString * str, guint indent_level);

TESTUTIL_TESTCASE (binary_diff)
{
  const guint8 expected_bytes[] = { 0x48, 0x8b, 0x40, 0x07 };
  const guint8 bad_bytes[] = { 0x4c, 0x8b, 0x40, 0x07 };
  const gchar * expected_diff = "In hex:\n"
                                "-------\n"
                                "\n"
                                "48 8b 40 07  <-- Expected\n"
                                " #\n"
                                "4c 8b 40 07  <-- Wrong\n"
                                "\n"
                                "In binary:\n"
                                "----------\n"
                                "\n"
                                "0100 1000  1000 1011  0100 0000  0000 0111  <-- Expected\n"
                                "      #\n"
                                "0100 1100  1000 1011  0100 0000  0000 0111  <-- Wrong\n";
  gchar * diff;

  diff = test_util_diff_binary (expected_bytes, sizeof (expected_bytes),
      bad_bytes, sizeof (bad_bytes));
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTUTIL_TESTCASE (text_diff)
{
  const gchar * expected_text = "Badger\nSnake\nMushroom";
  const gchar * bad_text      = "Badger\nSnakE\nMushroom";
  const gchar * expected_diff = "Badger\n"
                                "\n"
                                "Snake  <-- Expected\n"
                                "    #\n"
                                "SnakE  <-- Wrong\n"
                                "\n"
                                "Mushroom\n";
  gchar * diff;

  diff = test_util_diff_text (expected_text, bad_text);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTUTIL_TESTCASE (xml_pretty_split)
{
  const gchar * input_xml = "<foo><bar id=\"2\">Woot</bar></foo>";
  const gchar * expected_xml =
      "<foo>\n"
      "  <bar id=\"2\">\n"
      "    Woot\n"
      "  </bar>\n"
      "</foo>\n";
  gchar * output_xml;

  output_xml = prettify_xml (input_xml);
  g_assert_cmpstr (output_xml, ==, expected_xml);
  g_free (output_xml);
}

TESTUTIL_TESTCASE (xml_multiline_diff_same_size)
{
  const gchar * expected_xml = "<foo><bar id=\"4\"></bar></foo>";
  const gchar * bad_xml      = "<foo><bar id=\"5\"></bar></foo>";
  const gchar * expected_diff = "<foo>\n"
                                "\n"
                                "  <bar id=\"4\">  <-- Expected\n"
                                "           #\n"
                                "  <bar id=\"5\">  <-- Wrong\n"
                                "\n"
                                "  </bar>\n"
                                "</foo>\n";
  gchar * diff;

  diff = test_util_diff_xml (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTUTIL_TESTCASE (line_diff)
{
  const gchar * expected_xml = "<tag/>";
  const gchar * bad_xml = "<taG/>";
  const gchar * expected_diff = "\n"
                                "<tag/>  <-- Expected\n"
                                "   #\n"
                                "<taG/>  <-- Wrong\n";
  gchar * diff;

  diff = diff_line (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

/* Implementation */

GumSampler *
heap_access_counter_new (void)
{
  return gum_call_count_sampler_new (malloc, calloc, realloc, free,
      g_slice_alloc, g_slice_alloc0, g_slice_copy, g_slice_free1,
      g_slice_free_chain_with_offset, g_malloc, g_malloc0, g_free,
      g_memdup, NULL);
}

void
assert_basename_equals (const gchar * expected_filename,
                        const gchar * actual_filename)
{
  gchar * expected_basename, * actual_basename;

  expected_basename = g_path_get_basename (expected_filename);
  actual_basename = g_path_get_basename (actual_filename);

  g_assert_cmpstr (expected_basename, ==, actual_basename);

  g_free (expected_basename);
  g_free (actual_basename);
}

gchar *
test_util_diff_binary (const guint8 * expected_bytes,
                       guint expected_length,
                       const guint8 * actual_bytes,
                       guint actual_length)
{
  GString * full_diff;
  gchar * expected_str, * actual_str, * diff;

  full_diff = g_string_new ("In hex:\n");
  g_string_append (full_diff, "-------\n");
  expected_str = byte_array_to_hex_string (expected_bytes, expected_length);
  actual_str = byte_array_to_hex_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  g_string_append_c (full_diff, '\n');

  g_string_append (full_diff, "In binary:\n");
  g_string_append (full_diff, "----------\n");
  expected_str = byte_array_to_bin_string (expected_bytes, expected_length);
  actual_str = byte_array_to_bin_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_text (const gchar * expected_text,
                     const gchar * actual_text)
{
  GString * full_diff;
  gchar ** expected_lines, ** actual_lines;
  guint i;

  expected_lines = g_strsplit (expected_text, "\n", 0);
  actual_lines = g_strsplit (actual_text, "\n", 0);

  full_diff = g_string_sized_new (strlen (expected_text));

  for (i = 0; expected_lines[i] != NULL && actual_lines[i] != NULL; i++)
  {
    gchar * diff;

    if (expected_lines[i][0] == '\0' || actual_lines[i][0] == '\0')
      continue;

    diff = diff_line (expected_lines[i], actual_lines[i]);
    g_string_append (full_diff, diff);
    g_string_append_c (full_diff, '\n');
    g_free (diff);
  }

  g_strfreev (expected_lines);
  g_strfreev (actual_lines);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_xml (const gchar * expected_xml,
                    const gchar * actual_xml)
{
  gchar * expected_xml_pretty, * actual_xml_pretty, * diff;

  expected_xml_pretty = prettify_xml (expected_xml);
  actual_xml_pretty = prettify_xml (actual_xml);

  diff = test_util_diff_text (expected_xml_pretty, actual_xml_pretty);

  g_free (expected_xml_pretty);
  g_free (actual_xml_pretty);

  return diff;
}

static gchar *
byte_array_to_hex_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 2 + length - 1);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    if (byte_idx != 0)
      g_string_append_c (result, ' ');
    g_string_append_printf (result, "%02x", bytes[byte_idx]);
  }

  return g_string_free (result, FALSE);
}

static gchar *
byte_array_to_bin_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 9 + length * 2 - 2);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    guint bit_idx;

    if (byte_idx != 0)
      g_string_append (result, "  ");

    for (bit_idx = 0; bit_idx != 8; bit_idx++)
    {
      gboolean bit_is_set;

      bit_is_set = (bytes[byte_idx] >> (7 - bit_idx)) & 1;

      if (bit_idx == 4)
        g_string_append_c (result, ' ');
      g_string_append_c (result, bit_is_set ? '1' : '0');
    }
  }

  return g_string_free (result, FALSE);
}

typedef struct _PrettifyState PrettifyState;

struct _PrettifyState
{
  GString * output_xml;
  guint indentation_level;
};

static gchar *
prettify_xml (const gchar * input_xml)
{
  PrettifyState state;
  GMarkupParser parser = { NULL, };
  GMarkupParseContext * context;

  state.output_xml = g_string_sized_new (80);
  state.indentation_level = 0;

  parser.start_element = on_start_element;
  parser.end_element = on_end_element;
  parser.text = on_text;

  context = g_markup_parse_context_new (&parser, 0, &state, NULL);
  g_markup_parse_context_parse (context, input_xml, strlen (input_xml), NULL);
  g_markup_parse_context_free (context);

  return g_string_free (state.output_xml, FALSE);
}

static void
on_start_element (GMarkupParseContext * context,
                  const gchar * element_name,
                  const gchar ** attribute_names,
                  const gchar ** attribute_values,
                  gpointer user_data,
                  GError ** error)
{
  PrettifyState * state = user_data;
  guint i;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "<%s", element_name);

  for (i = 0; attribute_names[i] != NULL; i++)
  {
    g_string_append_printf (state->output_xml, " %s=\"%s\"",
        attribute_names[i], attribute_values[i]);
  }

  g_string_append (state->output_xml, ">\n");

  state->indentation_level++;
}

static void
on_end_element (GMarkupParseContext * context,
                const gchar * element_name,
                gpointer user_data,
                GError ** error)
{
  PrettifyState * state = user_data;

  state->indentation_level--;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "</%s>\n", element_name);
}

static void
on_text (GMarkupParseContext * context,
         const gchar * text,
         gsize text_len,  
         gpointer user_data,
         GError ** error)
{
  PrettifyState * state = user_data;

  if (text_len > 0)
  {
    append_indent (state->output_xml, state->indentation_level);
    g_string_append_len (state->output_xml, text, text_len);
    g_string_append_printf (state->output_xml, "\n");
  }
}

static gchar *
diff_line (const gchar * expected_line,
           const gchar * actual_line)
{
  GString * diff_str;
  guint diff_pos = 0;
  const gchar * expected = expected_line;
  const gchar * actual   = actual_line;

  if (strcmp (expected_line, actual_line) == 0)
    return g_strdup (actual_line);

  while (*expected != '\0' && *actual != '\0')
  {
    if (*expected != *actual)
    {
      diff_pos = expected - expected_line;
      break;
    }

    expected++;
    actual++;
  }

  diff_str = g_string_sized_new (80);
  g_string_append_c (diff_str, '\n');
  g_string_append_printf (diff_str, "%s  <-- Expected\n", expected_line);
  g_string_append_printf (diff_str, "%*s#\n", diff_pos, "");
  g_string_append_printf (diff_str, "%s  <-- Wrong\n", actual_line);

  return g_string_free (diff_str, FALSE);
}

static void
append_indent (GString * str,
               guint indent_level)
{
  guint i;

  for (i = 0; i < indent_level; i++)
    g_string_append (str, "  ");
}
