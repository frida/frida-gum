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

#include "gumsanitychecker.h"

#include "dummyclasses.h"
#include "testutil.h"

#include <string.h>

#define SANITYCHECKER_TESTCASE(NAME) \
    void test_sanity_checker_ ## NAME ( \
        TestSanityCheckerFixture * fixture, gconstpointer data)
#define SANITYCHECKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/SanityChecker", \
        test_sanity_checker, NAME, TestSanityCheckerFixture)

typedef struct _TestSanityCheckerFixture
{
  GumSanityChecker * checker;
  GString * output;

  gboolean run_returned_true;
  guint output_call_count;

  MyPony * first_pony;
  MyPony * second_pony;
  ZooZebra * first_zebra;
  ZooZebra * second_zebra;

  guint leak_flags;
} TestSanityCheckerFixture;

static void
test_sanity_checker_fixture_do_output (const gchar * text,
                                       gpointer user_data)
{
  TestSanityCheckerFixture * fixture = (TestSanityCheckerFixture *) user_data;

  fixture->output_call_count++;
  g_string_append (fixture->output, text);
}

static void
test_sanity_checker_fixture_setup (TestSanityCheckerFixture * fixture,
                                   gconstpointer data)
{
  fixture->output = g_string_new ("");

  fixture->checker = gum_sanity_checker_new (
      test_sanity_checker_fixture_do_output, fixture);
}

static void
test_sanity_checker_fixture_teardown (TestSanityCheckerFixture * fixture,
                                      gconstpointer data)
{
  if (fixture->first_pony != NULL)
    g_object_unref (fixture->first_pony);
  if (fixture->second_pony != NULL)
    g_object_unref (fixture->second_pony);

  if (fixture->first_zebra != NULL)
    g_object_unref (fixture->first_zebra);
  if (fixture->second_zebra != NULL)
    g_object_unref (fixture->second_zebra);

  gum_sanity_checker_destroy (fixture->checker);

  g_string_free (fixture->output, TRUE);
}

typedef enum _LeakFlags
{
  LEAK_FIRST_PONY     = (1 << 0),
  LEAK_SECOND_PONY    = (1 << 1),
  LEAK_FIRST_ZEBRA    = (1 << 2),
  LEAK_SECOND_ZEBRA   = (1 << 3)
} LeakFlags;

static void
simulation (gpointer user_data)
{
  TestSanityCheckerFixture * fixture = (TestSanityCheckerFixture *) user_data;

  fixture->first_pony = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  fixture->second_pony = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  fixture->first_zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));
  fixture->second_zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));

  if ((fixture->leak_flags & LEAK_FIRST_PONY) == 0)
  {
    g_object_unref (fixture->first_pony);
    fixture->first_pony = NULL;
  }
  if ((fixture->leak_flags & LEAK_SECOND_PONY) == 0)
  {
    g_object_unref (fixture->second_pony);
    fixture->second_pony = NULL;
  }

  if ((fixture->leak_flags & LEAK_FIRST_ZEBRA) == 0)
  {
    g_object_unref (fixture->first_zebra);
    fixture->first_zebra = NULL;
  }
  if ((fixture->leak_flags & LEAK_SECOND_ZEBRA) == 0)
  {
    g_object_unref (fixture->second_zebra);
    fixture->second_zebra = NULL;
  }
}

static void
run_simulation (TestSanityCheckerFixture * fixture,
                guint leak_flags)
{
  fixture->leak_flags = leak_flags;
  fixture->run_returned_true =
      gum_sanity_checker_run (fixture->checker, simulation, fixture);
}

static void
assert_same_output (TestSanityCheckerFixture * fixture,
                    const gchar * expected_output)
{
  gboolean is_exact_match;

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
}
