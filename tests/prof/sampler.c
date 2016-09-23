/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "sampler-fixture.c"

TEST_LIST_BEGIN (sampler)
  SAMPLER_TESTENTRY (cycle)
  SAMPLER_TESTENTRY (busy_cycle)
  SAMPLER_TESTENTRY (malloc_count)
  SAMPLER_TESTENTRY (multiple_call_counters)
  SAMPLER_TESTENTRY (wallclock)
TEST_LIST_END ()

static void spin_for_one_tenth_second (void);
static gpointer malloc_count_helper_thread (gpointer data);
static void nop_function_a (void);
static void nop_function_b (void);

SAMPLER_TESTCASE (cycle)
{
  GumSample sample_a, sample_b;

  fixture->sampler = gum_cycle_sampler_new ();
  if (gum_cycle_sampler_is_available (GUM_CYCLE_SAMPLER (fixture->sampler)))
  {
    sample_a = gum_sampler_sample (fixture->sampler);
    sample_b = gum_sampler_sample (fixture->sampler);
    g_assert_cmpuint (sample_a, !=, sample_b);
  }
  else
  {
    g_test_message ("skipping test because of unsupported OS");
  }
}

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

    g_assert_cmpuint (spin_diff, >, sleep_diff * 10);
  }
  else
  {
    g_test_message ("skipping test because of unsupported OS");
  }
}

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
  GumInterceptor * interceptor;
  volatile gpointer a, b, c = NULL;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  fixture->sampler = gum_malloc_count_sampler_new ();

  helper.sampler = fixture->sampler;
  helper_thread = g_thread_new ("sampler-test-malloc-count",
      malloc_count_helper_thread, &helper);

  interceptor = gum_interceptor_obtain ();

  sample_a = gum_sampler_sample (fixture->sampler);
  a = malloc (1);
  helper.allowed_to_start = TRUE;
  gum_interceptor_ignore_current_thread (interceptor);
  g_thread_join (helper_thread);
  gum_interceptor_unignore_current_thread (interceptor);
  b = calloc (2, 2);
  c = realloc (c, 6);
  free (c);
  free (b);
  free (a);
  sample_b = gum_sampler_sample (fixture->sampler);

  g_object_unref (interceptor);

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

static void
spin_for_one_tenth_second (void)
{
  GTimer * timer;
  guint i;
  guint b = 0;

  timer = g_timer_new ();

  do
  {
    for (i = 0; i != 1000000; i++)
      b += i * i;
  }
  while (g_timer_elapsed (timer, NULL) < 0.1);

  g_timer_destroy (timer);
}

static gpointer
malloc_count_helper_thread (gpointer data)
{
  MallocCountHelperContext * helper = (MallocCountHelperContext *) data;
  GumSample sample_a, sample_b;
  volatile gpointer p;

  while (!helper->allowed_to_start)
    g_thread_yield ();

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
