/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64stalker-fixture.c"

TEST_LIST_BEGIN (arm64stalker)
  STALKER_ARM64_TESTENTRY (no_events)
  STALKER_ARM64_TESTENTRY (heap_api)
  STALKER_ARM64_TESTENTRY (follow_syscall)
  STALKER_ARM64_TESTENTRY (follow_thread)
TEST_LIST_END ()

static void pretend_workload (void);
static gpointer stalker_victim (gpointer data);
static void invoke_follow_return_code (TestArm64StalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestArm64StalkerFixture * fixture);

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

static const guint32 flat_code[] = {
        0xCB000000, /* sub w0,w0,w0 */
        0x91000400, /* inc w0       */
        0x91000400, /* inc w0       */
        0xd65f03c0  /* ret          */
};

static const guint32 NEW_flat_code[] = {
        GUINT32_TO_LE(0xd10043ff),
        GUINT32_TO_LE(0xb9000fe0),
        GUINT32_TO_LE(0x52800040),
        GUINT32_TO_LE(0x910043ff),
        GUINT32_TO_LE(0xd65f03c0)
};

static StalkerTestFunc invoke_flat (TestArm64StalkerFixture * fixture,
                                    GumEventType mask)
{
    StalkerTestFunc func;
    gint ret;

    func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
                                   test_arm64_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

    fixture->sink->mask = mask;
    ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, -1);
    g_assert_cmpint (ret, ==, 2);

    return func;
}

STALKER_ARM64_TESTCASE (no_events)
{
    invoke_flat (fixture, GUM_NOTHING);
    g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

STALKER_ARM64_TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

STALKER_ARM64_TESTCASE (follow_syscall)
{
    fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

    gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
    g_usleep (1);
    gum_stalker_unfollow_me (fixture->stalker);

    g_assert_cmpuint (fixture->sink->events->len, >, 0);

                /*gum_fake_event_sink_dump (fixture->sink);*/
}

STALKER_ARM64_TESTCASE (follow_thread)
{
    StalkerVictimContext ctx;
    GumThreadId thread_id;
    GThread * thread;

    ctx.state = STALKER_VICTIM_CREATED;
    g_mutex_init (&ctx.mutex);
    g_cond_init (&ctx.cond);

    thread = g_thread_new ("stalker-test-victim", stalker_victim, &ctx);

    /* 1: Wait for victim to tell us it's ready, giving its thread id */
    g_mutex_lock (&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_FOLLOW)
        g_cond_wait (&ctx.cond, &ctx.mutex);
    thread_id = ctx.thread_id;
    g_mutex_unlock (&ctx.mutex);

    /* 4: Follow and notify victim about it */
    fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);
    gum_stalker_follow (fixture->stalker, thread_id,
        GUM_EVENT_SINK (fixture->sink));
    g_mutex_lock (&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_FOLLOWED;
    g_cond_signal (&ctx.cond);
    g_mutex_unlock (&ctx.mutex);

    /* 5: Wait for victim to tell us to unfollow */
    g_mutex_lock (&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_UNFOLLOW)
        g_cond_wait (&ctx.cond, &ctx.mutex);
    g_mutex_unlock (&ctx.mutex);

    g_assert_cmpuint (fixture->sink->events->len, >, 0);

    /* 8: Unfollow and notify victim about it */
    gum_stalker_unfollow (fixture->stalker, thread_id);
    g_mutex_lock (&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_UNFOLLOWED;
    g_cond_signal (&ctx.cond);
    g_mutex_unlock (&ctx.mutex);

    /* 9: Wait for victim to tell us it's ready for us to reset the sink */
    g_mutex_lock (&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_SHUTDOWN)
        g_cond_wait (&ctx.cond, &ctx.mutex);
    g_mutex_unlock (&ctx.mutex);

    gum_fake_event_sink_reset (fixture->sink);

    /* 12: Tell victim to it' */
    g_mutex_lock (&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_SHUTDOWN;
    g_cond_signal (&ctx.cond);
    g_mutex_unlock (&ctx.mutex);

    g_thread_join (thread);

    g_assert_cmpuint (fixture->sink->events->len, ==, 0);

    g_mutex_clear (&ctx.mutex);
    g_cond_clear (&ctx.cond);
}

static gpointer stalker_victim (gpointer data)
{
    StalkerVictimContext * ctx = (StalkerVictimContext *) data;

    g_mutex_lock (&ctx->mutex);

    /* 2: Signal readyness, giving our thread id */
    ctx->state = STALKER_VICTIM_READY_FOR_FOLLOW;
    ctx->thread_id = gum_process_get_current_thread_id ();
    g_cond_signal (&ctx->cond);

    /* 3: Wait for master to tell us we're being followed */
    while (ctx->state != STALKER_VICTIM_IS_FOLLOWED)
        g_cond_wait (&ctx->cond, &ctx->mutex);

    /* 6: Signal that we're ready to be unfollowed */
    ctx->state = STALKER_VICTIM_READY_FOR_UNFOLLOW;
    g_cond_signal (&ctx->cond);

    /* 7: Wait for master to tell us we're no longer followed */
    while (ctx->state != STALKER_VICTIM_IS_UNFOLLOWED)
        g_cond_wait (&ctx->cond, &ctx->mutex);

    /* 10: Signal that we're ready for a reset */
    ctx->state = STALKER_VICTIM_READY_FOR_SHUTDOWN;
    g_cond_signal (&ctx->cond);

    /* 11: Wait for master to tell us we can call it a day */
    while (ctx->state != STALKER_VICTIM_IS_SHUTDOWN)
        g_cond_wait (&ctx->cond, &ctx->mutex);

    g_mutex_unlock (&ctx->mutex);

    return NULL;
}