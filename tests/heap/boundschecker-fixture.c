/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumboundschecker.h"

#include "gummemory.h"
#include "testutil.h"

#include <stdlib.h>
#include <string.h>

#define BOUNDSCHECKER_TESTCASE(NAME) \
    void test_bounds_checker_ ## NAME ( \
        TestBoundsCheckerFixture * fixture, gconstpointer data)
#define BOUNDSCHECKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/BoundsChecker", \
        test_bounds_checker, NAME, TestBoundsCheckerFixture)

typedef struct _TestBoundsCheckerFixture
{
  GumBoundsChecker * checker;
  GString * output;
  guint output_call_count;
} TestBoundsCheckerFixture;

static void test_bounds_checker_fixture_do_output (const gchar * text,
    gpointer user_data);

static void
test_bounds_checker_fixture_setup (TestBoundsCheckerFixture * fixture,
                                   gconstpointer data)
{
  fixture->output = g_string_new ("");

  fixture->checker = gum_bounds_checker_new (
      test_bounds_checker_fixture_do_output, fixture);
}

static void
test_bounds_checker_fixture_teardown (TestBoundsCheckerFixture * fixture,
                                      gconstpointer data)
{
  g_object_unref (fixture->checker);

  g_string_free (fixture->output, TRUE);
}

static void
assert_same_output (TestBoundsCheckerFixture * fixture,
                    const gchar * expected_output_format,
                    ...)
{
  gboolean is_exact_match;
  va_list args;
  gchar * expected_output;

  va_start (args, expected_output_format);
  expected_output = g_strdup_vprintf (expected_output_format, args);
  va_end (args);

  is_exact_match = strcmp (fixture->output->str, expected_output) == 0;
  if (!is_exact_match)
  {
    GString * message;
    gchar * diff;

    message = g_string_new ("Generated output not like expected:\n\n");

    diff = test_util_diff_text (expected_output, fixture->output->str);
    g_string_append (message, diff);
    g_free (diff);

    g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC,
        message->str);

    g_string_free (message, TRUE);
  }

  g_free (expected_output);
}

static void
test_bounds_checker_fixture_do_output (const gchar * text,
                                       gpointer user_data)
{
  TestBoundsCheckerFixture * fixture = (TestBoundsCheckerFixture *) user_data;

  fixture->output_call_count++;
  g_string_append (fixture->output, text);
}

#define ATTACH_CHECKER() \
    gum_bounds_checker_attach_to_apis (fixture->checker, \
        test_util_heap_apis ())
#define DETACH_CHECKER() \
    gum_bounds_checker_detach (fixture->checker)
