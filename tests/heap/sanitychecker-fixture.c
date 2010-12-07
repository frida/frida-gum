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

  guint simulation_call_count;
  gboolean run_returned_true;
  guint output_call_count;

  MyPony * first_pony;
  MyPony * second_pony;
  ZooZebra * first_zebra;
  ZooZebra * second_zebra;

  gpointer first_block;
  gpointer second_block;
  gpointer third_block;

  GParamSpec * pspec;

  guint leak_flags;
} TestSanityCheckerFixture;

typedef enum _LeakFlags
{
  LEAK_FIRST_PONY     = (1 << 0),
  LEAK_SECOND_PONY    = (1 << 1),
  LEAK_FIRST_ZEBRA    = (1 << 2),
  LEAK_SECOND_ZEBRA   = (1 << 3),

  LEAK_FIRST_BLOCK    = (1 << 4),
  LEAK_SECOND_BLOCK   = (1 << 5),
  LEAK_THIRD_BLOCK    = (1 << 6),

  LEAK_GPARAM_ONCE    = (1 << 7),
} LeakFlags;

static void simulation (gpointer user_data);
static void test_sanity_checker_fixture_do_cleanup (
    TestSanityCheckerFixture * fixture);
static void test_sanity_checker_fixture_do_output (const gchar * text,
    gpointer user_data);

static void forget_block (gpointer * block);
static void forget_object (gpointer object);

static void
test_sanity_checker_fixture_setup (TestSanityCheckerFixture * fixture,
                                   gconstpointer data)
{
  fixture->output = g_string_new ("");

  fixture->checker = gum_sanity_checker_new_with_heap_apis (
      test_util_heap_apis (), test_sanity_checker_fixture_do_output, fixture);
}

static void
test_sanity_checker_fixture_teardown (TestSanityCheckerFixture * fixture,
                                      gconstpointer data)
{
  test_sanity_checker_fixture_do_cleanup (fixture);

  gum_sanity_checker_destroy (fixture->checker);

  g_string_free (fixture->output, TRUE);
}

static void
run_simulation (TestSanityCheckerFixture * fixture,
                guint leak_flags)
{
  fixture->leak_flags = leak_flags;
  fixture->simulation_call_count = 0;
  fixture->run_returned_true =
      gum_sanity_checker_run (fixture->checker, simulation, fixture);
}

static void
assert_same_output (TestSanityCheckerFixture * fixture,
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
simulation (gpointer user_data)
{
  TestSanityCheckerFixture * fixture = (TestSanityCheckerFixture *) user_data;

  fixture->simulation_call_count++;

  test_sanity_checker_fixture_do_cleanup (fixture);

  if ((fixture->leak_flags & (LEAK_FIRST_PONY | LEAK_SECOND_PONY |
      LEAK_FIRST_ZEBRA | LEAK_SECOND_ZEBRA)) != 0)
  {
    fixture->first_pony = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
    fixture->second_pony = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
    g_object_ref (fixture->second_pony);
    fixture->first_zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));
    fixture->second_zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));

    if ((fixture->leak_flags & LEAK_FIRST_PONY) == 0)
      forget_object (&fixture->first_pony);
    if ((fixture->leak_flags & LEAK_SECOND_PONY) == 0)
    {
      g_object_unref (fixture->second_pony);
      forget_object (&fixture->second_pony);
    }

    if ((fixture->leak_flags & LEAK_FIRST_ZEBRA) == 0)
      forget_object (&fixture->first_zebra);
    if ((fixture->leak_flags & LEAK_SECOND_ZEBRA) == 0)
      forget_object (&fixture->second_zebra);
  }

  if ((fixture->leak_flags & (LEAK_FIRST_BLOCK | LEAK_SECOND_BLOCK |
      LEAK_THIRD_BLOCK)) != 0)
  {
    fixture->first_block = g_malloc (5);
    fixture->second_block = g_malloc (10);
    fixture->third_block = g_malloc (15);

    /* just to get a group of size 42 with 0 objects alive: */
    g_free (g_malloc (42));

    if ((fixture->leak_flags & LEAK_FIRST_BLOCK) == 0)
      forget_block (&fixture->first_block);
    if ((fixture->leak_flags & LEAK_SECOND_BLOCK) == 0)
      forget_block (&fixture->second_block);
    if ((fixture->leak_flags & LEAK_THIRD_BLOCK) == 0)
      forget_block (&fixture->third_block);
  }

  if ((fixture->leak_flags & LEAK_GPARAM_ONCE) != 0 &&
      fixture->simulation_call_count > 1)
  {
    fixture->pspec = g_param_spec_int ("badger", "Badger", "Badger", 1, 10, 7,
        (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

    fixture->leak_flags &= ~LEAK_GPARAM_ONCE;
  }
}

static void
test_sanity_checker_fixture_do_cleanup (TestSanityCheckerFixture * fixture)
{
  if (fixture->pspec != NULL)
  {
    g_param_spec_unref (fixture->pspec);
    fixture->pspec = NULL;
  }

  forget_block (&fixture->first_block);
  forget_block (&fixture->second_block);
  forget_block (&fixture->third_block);

  forget_object (&fixture->first_pony);
  if (fixture->second_pony != NULL)
  {
    g_object_unref (fixture->second_pony);
    forget_object (&fixture->second_pony);
  }
  forget_object (&fixture->first_zebra);
  forget_object (&fixture->second_zebra);
}

static void
test_sanity_checker_fixture_do_output (const gchar * text,
                                       gpointer user_data)
{
  TestSanityCheckerFixture * fixture = (TestSanityCheckerFixture *) user_data;

  fixture->output_call_count++;
  g_string_append (fixture->output, text);
}

static void
forget_block (gpointer * block)
{
  g_free (*block);
  *block = NULL;
}

static void
forget_object (gpointer object)
{
  gpointer * ptr = (gpointer *) object;

  if (*ptr != NULL)
  {
    g_object_unref (*ptr);
    *ptr = NULL;
  }
}
