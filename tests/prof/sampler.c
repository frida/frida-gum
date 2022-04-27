/*
 * Copyright (C) 2008-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "sampler-fixture.c"

TESTLIST_BEGIN (sampler)
  TESTENTRY (cycle)
  TESTENTRY (busy_cycle)
#if defined (HAVE_FRIDA_GLIB) && !defined (HAVE_ASAN)
  TESTENTRY (malloc_count)
#endif
  TESTENTRY (multiple_call_counters)
  TESTENTRY (wallclock)
TESTLIST_END ()

static guint spin_for_one_tenth_second (void);
static void nop_function_a (void);
static void nop_function_b (void);

TESTCASE (cycle)
{
  GumSample sample_a, sample_b;

  fixture->sampler = gum_cycle_sampler_new ();
  if (gum_cycle_sampler_is_available (GUM_CYCLE_SAMPLER (fixture->sampler)))
  {
    sample_a = gum_sampler_sample (fixture->sampler);
    sample_b = gum_sampler_sample (fixture->sampler);
    g_assert_cmpuint (sample_b, >=, sample_a);
  }
  else
  {
    g_test_message ("skipping test because of unsupported OS");
  }
}

TESTCASE (busy_cycle)
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
  const GumHeapApi * api;
  volatile gboolean allowed_to_start;
  GumSample count;
};

#if defined (HAVE_FRIDA_GLIB) && !defined (HAVE_ASAN)

static gpointer malloc_count_helper_thread (gpointer data);

TESTCASE (malloc_count)
{
  const GumHeapApiList * heap_apis;
  const GumHeapApi * api;
  GumSample sample_a, sample_b;
  MallocCountHelperContext helper = { 0, };
  GThread * helper_thread;
  GumInterceptor * interceptor;
  volatile gpointer a, b, c = NULL;

#ifdef HAVE_QNX
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  heap_apis = test_util_heap_apis ();
  api = gum_heap_api_list_get_nth (heap_apis, 0);

  fixture->sampler = gum_malloc_count_sampler_new_with_heap_apis (heap_apis);

  helper.sampler = fixture->sampler;
  helper.api = api;
  helper_thread = g_thread_new ("sampler-test-malloc-count",
      malloc_count_helper_thread, &helper);

  interceptor = gum_interceptor_obtain ();

  sample_a = gum_sampler_sample (fixture->sampler);
  a = api->malloc (1);
  helper.allowed_to_start = TRUE;
  gum_interceptor_ignore_current_thread (interceptor);
  g_thread_join (helper_thread);
  gum_interceptor_unignore_current_thread (interceptor);
  b = api->calloc (2, 2);
  c = api->realloc (c, 6);
  api->free (c);
  api->free (b);
  api->free (a);
  sample_b = gum_sampler_sample (fixture->sampler);

  g_object_unref (interceptor);

  g_assert_cmpuint (sample_b, ==, sample_a + 3);
  g_assert_cmpuint (helper.count, ==, 1);
  g_assert_cmpuint (gum_call_count_sampler_peek_total_count (
      GUM_CALL_COUNT_SAMPLER (fixture->sampler)), >=, 3 + 1);
}

static gpointer
malloc_count_helper_thread (gpointer data)
{
  MallocCountHelperContext * helper = (MallocCountHelperContext *) data;
  const GumHeapApi * api = helper->api;
  GumSample sample_a, sample_b;
  volatile gpointer p;

  while (!helper->allowed_to_start)
    g_thread_yield ();

  sample_a = gum_sampler_sample (helper->sampler);
  p = api->malloc (3);
  api->free (p);
  sample_b = gum_sampler_sample (helper->sampler);

  helper->count = sample_b - sample_a;

  return NULL;
}

#endif

TESTCASE (multiple_call_counters)
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

TESTCASE (wallclock)
{
  GumSample sample_a, sample_b;

  fixture->sampler = gum_wallclock_sampler_new ();

  sample_a = gum_sampler_sample (fixture->sampler);
  g_usleep (G_USEC_PER_SEC / 30);
  sample_b = gum_sampler_sample (fixture->sampler);

  g_assert_cmpuint (sample_b, >, sample_a);
}

static guint
spin_for_one_tenth_second (void)
{
  guint b = 0;
  GTimer * timer;
  guint i;

  timer = g_timer_new ();

  do
  {
    for (i = 0; i != 1000000; i++)
      b += i * i;
  }
  while (g_timer_elapsed (timer, NULL) < 0.1);

  g_timer_destroy (timer);

  return b;
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
