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

#include "gummemory-priv.h"

#define MEMORY_TESTCASE(NAME) \
    void test_memory_ ## NAME (void)
#define MEMORY_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Memory", test_memory, NAME)

TEST_LIST_BEGIN (memory)
  MEMORY_TESTENTRY (match_pattern_validation)
  MEMORY_TESTENTRY (scan_range_with_three_exact_matches)
  MEMORY_TESTENTRY (scan_range_with_three_wildcarded_matches)
TEST_LIST_END ()

typedef struct _TestForEachContext {
  gboolean value_to_return;
  guint number_of_calls;

  gpointer expected_address[3];
  guint expected_size;
} TestForEachContext;

static gboolean match_found_cb (gpointer address, guint size,
    gpointer user_data);

#define GUM_PATTERN_NTH_TOKEN(p, n) \
    ((GumMatchToken *) g_ptr_array_index (p->tokens, n))
#define GUM_PATTERN_NTH_TOKEN_NTH_BYTE(p, n, b) \
    (g_array_index (((GumMatchToken *) g_ptr_array_index (p->tokens, \
        n))->bytes, guint8, b))

MEMORY_TESTCASE (match_pattern_validation)
{
  GumMatchPattern * pattern;

  pattern = gum_match_pattern_new_from_string ("1337");
  g_assert (pattern != NULL);
  g_assert_cmpuint (pattern->size, ==, 2);
  g_assert_cmpuint (pattern->tokens->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 2);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 1), ==, 0x37);
  gum_match_pattern_free (pattern);

  pattern = gum_match_pattern_new_from_string ("13 37");
  g_assert (pattern != NULL);
  g_assert_cmpuint (pattern->size, ==, 2);
  g_assert_cmpuint (pattern->tokens->len, ==, 1);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 2);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 1), ==, 0x37);
  gum_match_pattern_free (pattern);

  pattern = gum_match_pattern_new_from_string ("1 37");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("13 3");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("13+37");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("13 ?? 37");
  g_assert (pattern != NULL);
  g_assert_cmpuint (pattern->size, ==, 3);
  g_assert_cmpuint (pattern->tokens->len, ==, 3);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 0)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 0, 0), ==, 0x13);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 1)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 1, 0), ==, 0x42);
  g_assert_cmpuint (GUM_PATTERN_NTH_TOKEN (pattern, 2)->bytes->len, ==, 1);
  g_assert_cmphex (GUM_PATTERN_NTH_TOKEN_NTH_BYTE (pattern, 2, 0), ==, 0x37);
  gum_match_pattern_free (pattern);

  pattern = gum_match_pattern_new_from_string ("13 ? 37");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("??");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("?? 13");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("13 ??");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string (" ");
  g_assert (pattern == NULL);

  pattern = gum_match_pattern_new_from_string ("");
  g_assert (pattern == NULL);
}

MEMORY_TESTCASE (scan_range_with_three_exact_matches)
{
  guint8 buf[] = {
    0x13, 0x37,
    0x12,
    0x13, 0x37,
    0x13, 0x37
  };
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = buf;
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("13 37");
  g_assert (pattern != NULL);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + 2 + 1;
  ctx.expected_address[2] = buf + 2 + 1 + 2;
  ctx.expected_size = 2;

  gum_memory_scan (&range, pattern, match_found_cb, &ctx);

  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  gum_match_pattern_free (pattern);
}

MEMORY_TESTCASE (scan_range_with_three_wildcarded_matches)
{
  guint8 buf[] = {
    0x12, 0x11, 0x13, 0x37,
    0x12, 0x00,
    0x12, 0xc0, 0x13, 0x37,
    0x12, 0x44, 0x13, 0x37
  };
  GumMemoryRange range;
  GumMatchPattern * pattern;
  TestForEachContext ctx;

  range.base_address = buf;
  range.size = sizeof (buf);

  pattern = gum_match_pattern_new_from_string ("12 ?? 13 37");
  g_assert (pattern != NULL);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;

  ctx.expected_address[0] = buf + 0;
  ctx.expected_address[1] = buf + 4 + 2;
  ctx.expected_address[2] = buf + 4 + 2 + 4;
  ctx.expected_size = 4;

  gum_memory_scan (&range, pattern, match_found_cb, &ctx);

  g_assert_cmpuint (ctx.number_of_calls, ==, 3);

  gum_match_pattern_free (pattern);
}

static gboolean
match_found_cb (gpointer address,
                guint size,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  g_assert_cmpuint (ctx->number_of_calls, <, 3);

  g_assert (address == ctx->expected_address[ctx->number_of_calls]);
  g_assert_cmpuint (size, ==, ctx->expected_size);

  ctx->number_of_calls++;

  return ctx->value_to_return;
}