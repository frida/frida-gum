/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumsampler.h"

#include "testutil.h"

#include <stdlib.h>

#ifdef G_OS_WIN32
static void spin_for_one_tenth_second (void);
#endif
static gpointer malloc_count_helper_thread (gpointer data);
static void nop_function_a (void);
static void nop_function_b (void);

#define SAMPLER_TESTCASE(NAME) \
    void test_sampler_ ## NAME ( \
        TestSamplerFixture * fixture, gconstpointer data)
#define SAMPLER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Prof/Sampler", test_sampler, NAME, \
        TestSamplerFixture)

typedef struct _TestSamplerFixture
{
  GumSampler * sampler;
} TestSamplerFixture;

static void
test_sampler_fixture_setup (TestSamplerFixture * fixture,
                            gconstpointer data)
{
}

static void
test_sampler_fixture_teardown (TestSamplerFixture * fixture,
                               gconstpointer data)
{
  if (fixture->sampler != NULL)
    g_object_unref (fixture->sampler);
}

TEST_LIST_BEGIN (sampler)
  SAMPLER_TESTENTRY (cycle)
#ifdef G_OS_WIN32
  SAMPLER_TESTENTRY (busy_cycle)
#endif
  SAMPLER_TESTENTRY (malloc_count)
  SAMPLER_TESTENTRY (multiple_call_counters)
  SAMPLER_TESTENTRY (wallclock)
TEST_LIST_END ()

SAMPLER_TESTCASE (cycle)
{
  GumSample sample_a, sample_b;

  fixture->sampler = gum_cycle_sampler_new ();
  sample_a = gum_sampler_sample (fixture->sampler);
  sample_b = gum_sampler_sample (fixture->sampler);
  g_assert_cmpuint (sample_a, !=, sample_b);
}

#ifdef G_OS_WIN32
SAMPLER_TESTCASE (busy_cycle)
{
  GumSample spin_start, spin_diff;
  GumSample sleep_start, sleep_diff;

  fixture->sampler = gum_busy_cycle_sampler_new ();

  if (gum_busy_cycle_sampler_is_available (
      GUM_BUSY_CYCLE_SAMPLER (fixture->sampler)))
  {
    spin_start = gum_sampler_sample (fixture->sampler);
    spin_for_one_tenth_second ();
    spin_diff = gum_sampler_sample (fixture->sampler) - spin_start;

    sleep_start = gum_sampler_sample (fixture->sampler);
    g_usleep (G_USEC_PER_SEC / 10 / 10);
    sleep_diff = gum_sampler_sample (fixture->sampler) - sleep_start;

    g_assert_cmpuint (spin_diff, >, sleep_diff * 100);
  }
  else
  {
    g_test_message ("skipping test because of unsupported OS");
  }
}
#endif

typedef struct _MallocCountHelperContext MallocCountHelperContext;

struct _MallocCountHelperContext
{
  GumSampler * sampler;
  volatile gboolean allowed_to_start;
  GumSample count;
};

SAMPLER_TESTCASE (malloc_count)
{
  GumSample sample_a, sample_b;
  MallocCountHelperContext helper = { 0, };
  GThread * helper_thread;
  gpointer a, b, c = NULL;

  fixture->sampler = gum_malloc_count_sampler_new ();

  helper.sampler = fixture->sampler;
  helper_thread = g_thread_create (malloc_count_helper_thread, &helper, TRUE,
      NULL);

  sample_a = gum_sampler_sample (fixture->sampler);
  a = malloc (1);
  helper.allowed_to_start = TRUE;
  g_thread_join (helper_thread);
  b = calloc (2, 2);
  c = realloc (c, 6);
  free (c);
  free (b);
  free (a);
  sample_b = gum_sampler_sample (fixture->sampler);

  g_assert_cmpuint (sample_b, ==, sample_a + 3);
  g_assert_cmpuint (helper.count, ==, 1);
  g_assert_cmpuint (gum_call_count_sampler_peek_total_count (
      GUM_CALL_COUNT_SAMPLER (fixture->sampler)), >=, 3 + 1);
}

SAMPLER_TESTCASE (multiple_call_counters)
{
  GumSampler * sampler1, * sampler2;

  sampler1 = gum_call_count_sampler_new (nop_function_a, NULL);
  sampler2 = gum_call_count_sampler_new (nop_function_b, NULL);

  nop_function_a ();

  g_assert_cmpint (gum_sampler_sample (sampler1), ==, 1);
  g_assert_cmpint (gum_sampler_sample (sampler2), ==, 0);

  g_object_unref (sampler2);
  g_object_unref (sampler1);
}

SAMPLER_TESTCASE (wallclock)
{
  GumSample sample_a, sample_b;

  fixture->sampler = gum_wallclock_sampler_new ();

  sample_a = gum_sampler_sample (fixture->sampler);
  g_usleep (G_USEC_PER_SEC / 30);
  sample_b = gum_sampler_sample (fixture->sampler);

  g_assert_cmpuint (sample_b, >, sample_a);
}

#ifdef G_OS_WIN32
static void
spin_for_one_tenth_second (void)
{
  GTimer * timer;
  guint i;
  guint b = 0;

  timer = g_timer_new ();

  do
  {
    for (i = 0; i < 1000000; i++)
      b += i * i;
  }
  while (g_timer_elapsed (timer, NULL) < 0.1);

  g_timer_destroy (timer);
}
#endif

static gpointer
malloc_count_helper_thread (gpointer data)
{
  MallocCountHelperContext * helper = data;
  GumSample sample_a, sample_b;
  gpointer p;

  while (!helper->allowed_to_start)
    ;

  sample_a = gum_sampler_sample (helper->sampler);
  p = malloc (3);
  free (p);
  sample_b = gum_sampler_sample (helper->sampler);

  helper->count = sample_b - sample_a;

  return NULL;
}

static gint dummy_variable_to_trick_optimizer = 0;

static void GUM_NOINLINE
nop_function_a (void)
{
  dummy_variable_to_trick_optimizer += 3;
}

static void GUM_NOINLINE
nop_function_b (void)
{
  dummy_variable_to_trick_optimizer -= 7;
}
