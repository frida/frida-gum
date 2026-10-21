/*
 * Copyright (C) 2026 Thanos Petsas <thanpetsas@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumunwindbroker-priv.h"
#include "testutil.h"

#define GUM_TEST_ACTIVATION_ROUNDS 1000
#define GUM_TEST_THROWER_COUNT 8

#define TESTCASE(NAME) \
    void test_unwind_broker_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/UnwindBroker", test_unwind_broker, NAME)

TESTLIST_BEGIN (unwind_broker)
  TESTENTRY (exceptions_are_safe_during_activation)
TESTLIST_END ()

typedef struct _GumTestThrowerState GumTestThrowerState;

struct _GumTestThrowerState
{
  gint running;
  gint paused;
  gint idle_count;
  gint failure_count;
  gint throw_count;
};

gboolean gum_test_unwind_broker_throw_and_catch (gint value);

static gpointer gum_test_thrower (gpointer data);
static void gum_test_pause_throwers (GumTestThrowerState * state);
static void gum_test_resume_throwers (GumTestThrowerState * state);

TESTCASE (exceptions_are_safe_during_activation)
{
  GumInterceptor * interceptor;
  GumTestThrowerState state = { 0, };
  GThread * threads[GUM_TEST_THROWER_COUNT];
  guint i;

  state.running = TRUE;
  for (i = 0; i != G_N_ELEMENTS (threads); i++)
  {
    threads[i] = g_thread_new ("unwind-broker-thrower", gum_test_thrower,
        &state);
  }
  while (g_atomic_int_get (&state.throw_count) == 0)
    g_thread_yield ();

  interceptor = gum_interceptor_obtain ();

  for (i = 0; i != GUM_TEST_ACTIVATION_ROUNDS; i++)
  {
    gum_test_pause_throwers (&state);
    _gum_unwind_broker_backend_deactivate ();
    gum_test_resume_throwers (&state);

    _gum_unwind_broker_backend_activate (interceptor);
  }

  g_atomic_int_set (&state.running, FALSE);
  for (i = 0; i != G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);

  g_object_unref (interceptor);

  g_assert_cmpint (state.failure_count, ==, 0);
}

static gpointer
gum_test_thrower (gpointer data)
{
  GumTestThrowerState * state = data;
  gint value = 0;

  while (g_atomic_int_get (&state->running))
  {
    if (g_atomic_int_get (&state->paused))
    {
      g_atomic_int_inc (&state->idle_count);
      while (g_atomic_int_get (&state->paused) &&
          g_atomic_int_get (&state->running))
      {
        g_thread_yield ();
      }
      g_atomic_int_add (&state->idle_count, -1);
      continue;
    }

    if (!gum_test_unwind_broker_throw_and_catch (++value))
      g_atomic_int_inc (&state->failure_count);
    g_atomic_int_inc (&state->throw_count);
  }

  return NULL;
}

static void
gum_test_pause_throwers (GumTestThrowerState * state)
{
  g_atomic_int_set (&state->paused, TRUE);
  while (g_atomic_int_get (&state->idle_count) != GUM_TEST_THROWER_COUNT)
    g_thread_yield ();
}

static void
gum_test_resume_throwers (GumTestThrowerState * state)
{
  g_atomic_int_set (&state->paused, FALSE);
  while (g_atomic_int_get (&state->idle_count) != 0)
    g_thread_yield ();
}
