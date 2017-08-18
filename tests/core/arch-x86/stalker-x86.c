/*
 * Copyright (C) 2009-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-x86-fixture.c"

TEST_LIST_BEGIN (stalker)
  STALKER_TESTENTRY (no_events)
  STALKER_TESTENTRY (call)
  STALKER_TESTENTRY (ret)
  STALKER_TESTENTRY (exec)
  STALKER_TESTENTRY (call_depth)
  STALKER_TESTENTRY (call_probe)
  STALKER_TESTENTRY (custom_transformer)

  STALKER_TESTENTRY (unconditional_jumps)
  STALKER_TESTENTRY (short_conditional_jump_true)
  STALKER_TESTENTRY (short_conditional_jump_false)
  STALKER_TESTENTRY (short_conditional_jcxz_true)
  STALKER_TESTENTRY (short_conditional_jcxz_false)
  STALKER_TESTENTRY (long_conditional_jump)
  STALKER_TESTENTRY (follow_return)
  STALKER_TESTENTRY (follow_stdcall)
  STALKER_TESTENTRY (follow_repne_ret)
  STALKER_TESTENTRY (follow_repne_jb)
  STALKER_TESTENTRY (unfollow_deep)
  STALKER_TESTENTRY (call_followed_by_junk)
  STALKER_TESTENTRY (indirect_call_with_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_no_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_positive_byte_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_negative_byte_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_positive_dword_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_negative_dword_immediate)
#if GLIB_SIZEOF_VOID_P == 8
  STALKER_TESTENTRY (indirect_call_with_extended_registers_and_immediate)
#endif
  STALKER_TESTENTRY (indirect_call_with_esp_and_byte_immediate)
  STALKER_TESTENTRY (indirect_call_with_esp_and_dword_immediate)
  STALKER_TESTENTRY (indirect_jump_with_immediate)
  STALKER_TESTENTRY (indirect_jump_with_immediate_and_scaled_register)
  STALKER_TESTENTRY (direct_call_with_register)
#if GLIB_SIZEOF_VOID_P == 8
  STALKER_TESTENTRY (direct_call_with_extended_register)
#endif
  STALKER_TESTENTRY (popcnt)
#if GLIB_SIZEOF_VOID_P == 4
  STALKER_TESTENTRY (no_register_clobber)
#endif
  STALKER_TESTENTRY (no_red_zone_clobber)
  STALKER_TESTENTRY (big_block)

  STALKER_TESTENTRY (heap_api)
  STALKER_TESTENTRY (follow_syscall)
  STALKER_TESTENTRY (follow_thread)
  STALKER_TESTENTRY (performance)

#ifdef G_OS_WIN32
# if GLIB_SIZEOF_VOID_P == 4
  STALKER_TESTENTRY (win32_indirect_call_seg)
# endif
  STALKER_TESTENTRY (win32_messagebeep_api)
  STALKER_TESTENTRY (win32_follow_user_to_kernel_to_callback)
  STALKER_TESTENTRY (win32_follow_callback_to_kernel_to_user)
#endif
TEST_LIST_END ()

static void pretend_workload (void);
static gpointer stalker_victim (gpointer data);
static void insert_extra_increment_after_xor (GumStalkerIterator * iterator,
    GumStalkerWriter * output, gpointer user_data);
static void invoke_follow_return_code (TestStalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestStalkerFixture * fixture);

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

STALKER_TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

STALKER_TESTCASE (follow_syscall)
{
#ifdef G_OS_WIN32
  if (!g_test_slow ())
  {
    g_print ("<not yet stable on this OS; skipping, run in slow mode> ");
    return;
  }
#endif

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

STALKER_TESTCASE (follow_thread)
{
  StalkerVictimContext ctx;
  GumThreadId thread_id;
  GThread * thread;

#if defined (G_OS_WIN32) || defined (HAVE_LINUX)
  if (!g_test_slow ())
  {
    g_print ("<not yet stable on this OS; skipping, run in slow mode> ");
    return;
  }
#endif

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
  gum_stalker_follow (fixture->stalker, thread_id, NULL,
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

static gpointer
stalker_victim (gpointer data)
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

STALKER_TESTCASE (performance)
{
  GTimer * timer;
  gdouble duration_direct, duration_stalked;

#ifdef G_OS_WIN32
  if (!g_test_slow ())
  {
    g_print ("<not yet stable on this OS; skipping, run in slow mode> ");
    return;
  }
#endif

  timer = g_timer_new ();
  pretend_workload ();

  g_timer_reset (timer);
  pretend_workload ();
  duration_direct = g_timer_elapsed (timer, NULL);

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  /* warm-up */
  g_timer_reset (timer);
  pretend_workload ();
  g_timer_elapsed (timer, NULL);

  /* the real deal */
  g_timer_reset (timer);
  pretend_workload ();
  duration_stalked = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("<duration_direct=%f duration_stalked=%f ratio=%f> ",
      duration_direct, duration_stalked, duration_stalked / duration_direct);
}

GUM_NOINLINE static void
pretend_workload (void)
{
  const guint repeats = 250;
  guint i;

  for (i = 0; i != repeats; i++)
  {
    void * p = malloc (42 + i);
    gum_stalker_dummy_global_to_trick_optimizer +=
        GPOINTER_TO_SIZE (p) % 42 == 0;
    free (p);
  }
}

static const guint8 flat_code[] = {
    0x33, 0xc0, /* xor eax, eax */
    0xff, 0xc0, /* inc eax      */
    0xff, 0xc0, /* inc eax      */
    0xc3        /* retn         */
};

static StalkerTestFunc
invoke_flat_expecting_return_value (TestStalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat (TestStalkerFixture * fixture,
             GumEventType mask)
{
  return invoke_flat_expecting_return_value (fixture, mask, 2);
}

STALKER_TESTCASE (no_events)
{
  invoke_flat (fixture, GUM_NOTHING);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

STALKER_TESTCASE (call)
{
  StalkerTestFunc func;
  GumCallEvent * ev;

  func = invoke_flat (fixture, GUM_CALL);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_CALL);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->last_invoke_calladdr);
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
}

STALKER_TESTCASE (ret)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_RET);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_RET);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location,
      ==, ((guint8 *) GSIZE_TO_POINTER (func)) + 6);
  GUM_ASSERT_CMPADDR (ev->target, ==, fixture->last_invoke_retaddr);
}

STALKER_TESTCASE (exec)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).type, ==, GUM_EXEC);
  ev = &g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);
}

STALKER_TESTCASE (call_depth)
{
  const guint8 code[] =
  {
    0xb8, 0x07, 0x00, 0x00, 0x00, /* mov eax, 7 */
    0xff, 0xc8,                   /* dec eax    */
    0x74, 0x05,                   /* jz +5      */
    0xe8, 0xf7, 0xff, 0xff, 0xff, /* call -9    */
    0xc3,                         /* ret        */
    0xcc,                         /* int3       */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_CALL | GUM_RET;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, 7 + 7 + 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (0)->depth, ==, 0);
  g_assert_cmpint (NTH_EVENT_AS_CALL (1)->depth, ==, 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (2)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_CALL (3)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_CALL (4)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_CALL (5)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_CALL (6)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (7)->depth, ==, 7);
  g_assert_cmpint (NTH_EVENT_AS_RET (8)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (9)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_RET (10)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_RET (11)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_RET (12)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_RET (13)->depth, ==, 1);
}

typedef struct _CallProbeContext CallProbeContext;

struct _CallProbeContext
{
  guint callback_count;
  guint8 * block_start;
};

static void probe_func_a_invocation (GumCallSite * site, gpointer user_data);

STALKER_TESTCASE (call_probe)
{
  const guint8 code_template[] =
  {
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xaaaa4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xaaaa3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xaaaa2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xaaaa1111 */
    0xe8, 0x1b, 0x00, 0x00, 0x00, /* call func_a         */
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xbbbb4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xbbbb3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xbbbb2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xbbbb1111 */
    0xe8, 0x06, 0x00, 0x00, 0x00, /* call func_b         */
    0xc3,                         /* ret                 */

    0xcc,                         /* int 3               */

    /* func_a: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */

    0xcc,                         /* int 3               */

    /* func_b: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */
  };
  StalkerTestFunc func;
  guint8 * func_a_address;
  CallProbeContext probe_ctx, secondary_probe_ctx;
  GumProbeId probe_id;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code_template,
          sizeof (code_template)));

  func_a_address = fixture->code + 52;

  probe_ctx.callback_count = 0;
  probe_ctx.block_start = fixture->code;
  probe_id = gum_stalker_add_call_probe (fixture->stalker,
      func_a_address, probe_func_a_invocation, &probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 1);

  secondary_probe_ctx.callback_count = 0;
  secondary_probe_ctx.block_start = fixture->code;
  gum_stalker_add_call_probe (fixture->stalker,
      func_a_address, probe_func_a_invocation, &secondary_probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.callback_count, ==, 1);

  gum_stalker_remove_call_probe (fixture->stalker, probe_id);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.callback_count, ==, 2);
}

static void
probe_func_a_invocation (GumCallSite * site,
                         gpointer user_data)
{
  CallProbeContext * ctx = (CallProbeContext *) user_data;

  ctx->callback_count++;

  GUM_ASSERT_CMPADDR (site->block_address, ==, ctx->block_start);
#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (site->cpu_context->ecx, ==, 0xaaaa1111);
  g_assert_cmphex (site->cpu_context->edx, ==, 0xaaaa2222);
#else
  g_assert_cmphex (site->cpu_context->rcx & 0xffffffff, ==, 0xaaaa1111);
  g_assert_cmphex (site->cpu_context->rdx & 0xffffffff, ==, 0xaaaa2222);
#endif
  g_assert_cmphex (((gsize *) site->stack_data)[0] & 0xffffffff,
      ==, 0xaaaa3333);
  g_assert_cmphex (((gsize *) site->stack_data)[1] & 0xffffffff,
      ==, 0xaaaa4444);
}

static const guint8 jumpy_code[] = {
    0x31, 0xc0,                   /* xor eax, eax */
    0xeb, 0x01,                   /* jmp short +1 */
    0xcc,                         /* int3         */
    0xff, 0xc0,                   /* inc eax      */
    0xe9, 0x02, 0x00, 0x00, 0x00, /* jmp near +2  */
    0xcc,                         /* int3         */
    0xcc,                         /* int3         */
    0xc3                          /* ret          */
};

static StalkerTestFunc
invoke_jumpy (TestStalkerFixture * fixture,
              GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, jumpy_code, sizeof (jumpy_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 1);

  return func;
}

STALKER_TESTCASE (custom_transformer)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_extra_increment_after_xor, NULL, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 3);
}

static void
insert_extra_increment_after_xor (GumStalkerIterator * iterator,
                                  GumStalkerWriter * output,
                                  gpointer user_data)
{
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->id == X86_INS_XOR)
      gum_x86_writer_put_inc_reg (&output->x86, GUM_REG_EAX);
  }
}

STALKER_TESTCASE (unconditional_jumps)
{
  invoke_jumpy (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 14);
}

static StalkerTestFunc
invoke_short_condy (TestStalkerFixture * fixture,
                    GumEventType mask,
                    gint arg)
{
  const guint8 code[] = {
      0x83, 0xf9, 0x2a,             /* cmp ecx, 42    */
      0x74, 0x05,                   /* jz +5          */
      0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

      0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
      0xc3,                         /* ret            */

      0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
      0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 42) ? 1337 : 1227);

  return func;
}

STALKER_TESTCASE (short_conditional_jump_true)
{
  invoke_short_condy (fixture, GUM_EXEC, 42);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 10);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 15);
}

STALKER_TESTCASE (short_conditional_jump_false)
{
  invoke_short_condy (fixture, GUM_EXEC, 43);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 16);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 21);
}

static StalkerTestFunc
invoke_short_jcxz (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
    0xe3, 0x05,                   /* jecxz/jrcxz +5 */
    0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

    0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
    0xc3,                         /* ret            */

    0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
    0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 0) ? 1337 : 1227);

  return func;
}

STALKER_TESTCASE (short_conditional_jcxz_true)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 12);
}

STALKER_TESTCASE (short_conditional_jcxz_false)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0x11223344);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 13);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 18);
}

static StalkerTestFunc
invoke_long_condy (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
      0xe9, 0x0c, 0x01, 0x00, 0x00,         /* jmp +268             */

      0xb8, 0x39, 0x05, 0x00, 0x00,         /* mov eax, 1337        */
      0xc3,                                 /* ret                  */

      0xb8, 0xcb, 0x04, 0x00, 0x00,         /* mov eax, 1227        */
      0xc3,                                 /* ret                  */

      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,

      0x81, 0xc1, 0xff, 0xff, 0xff, 0xff,   /* add ecx, G_MAXUINT32 */
      0x0f, 0x83, 0xee, 0xfe, 0xff, 0xff,   /* jnc dword -274       */
      0xe9, 0xe3, 0xfe, 0xff, 0xff,         /* jmp dword -285       */
  };
  StalkerTestFunc func;
  gint ret;

  g_assert (arg == FALSE || arg == TRUE);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == TRUE) ? 1337 : 1227);

  return func;
}

STALKER_TESTCASE (long_conditional_jump)
{
  invoke_long_condy (fixture, GUM_EXEC, TRUE);
  invoke_long_condy (fixture, GUM_EXEC, FALSE);
}

#if GLIB_SIZEOF_VOID_P == 4
# define FOLLOW_RETURN_EXTRA_INSN_COUNT 2
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 3
# else
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 1
# endif
#endif

STALKER_TESTCASE (follow_return)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_follow_return_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 5 + FOLLOW_RETURN_EXTRA_INSN_COUNT);
}

static void
invoke_follow_return_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 12;
  guint align_correction_unfollow = 8;
#else
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 8;
#endif
  const gchar * start_following_lbl = "start_following";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_call_near_label (&cw, start_following_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, start_following_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

STALKER_TESTCASE (follow_stdcall)
{
  const guint8 stdcall_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0xe8, 0x02, 0x00, 0x00, 0x00, /* call func         */
    0xc3,                         /* ret               */
    0xcc,                         /* int3              */

  /* func: */
    0x8b, 0x44, 0x24,             /* mov eax, [esp+X]  */
          sizeof (gpointer),
    0xc2, sizeof (gpointer), 0x00 /* ret X             */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, stdcall_code,
          sizeof (stdcall_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

STALKER_TESTCASE (follow_repne_ret)
{
  const guint8 repne_ret_code[] =
  {
    0xb8, 0xef, 0xbe, 0x00, 0x00, /* mov eax, 0xbeef     */
    0xf2, 0xc3,                   /* repne ret           */
    0xcc,                         /* int3                */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_ret_code,
          sizeof (repne_ret_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 2);

  g_assert_cmpint (ret, ==, 0xbeef);
}

STALKER_TESTCASE (follow_repne_jb)
{
  const guint8 repne_jb_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef   */
    0xb8, 0xff, 0x00, 0x00, 0x00, /* mov eax, 0xff       */
    0xb9, 0xfe, 0x00, 0x00, 0x00, /* mov ecx, 0xfe       */
    0x3b, 0xc8,                   /* cmp ecx, eax        */
    0xf2, 0x72, 0x02,             /* repne jb short func */
    0xc3,                         /* ret                 */
    0xcc,                         /* int3                */

                                  /* func:               */
    0x58,                         /* pop eax             */
    0xc3,                         /* ret                 */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_jb_code,
          sizeof (repne_jb_code)));

  g_assert_cmpint (func (0), ==, 0xbeef);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  g_assert_cmpint (ret, ==, 0xbeef);
}

#if GLIB_SIZEOF_VOID_P == 4
#define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 1
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 2
# else
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 0
# endif
#endif

STALKER_TESTCASE (unfollow_deep)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_unfollow_deep_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 7 + UNFOLLOW_DEEP_EXTRA_INSN_COUNT);
}

static void
invoke_unfollow_deep_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 12;
#else
  guint align_correction_follow = 8;
  guint align_correction_unfollow = 0;
#endif
  const gchar * func_a_lbl = "func_a";
  const gchar * func_b_lbl = "func_b";
  const gchar * func_c_lbl = "func_c";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_near_label (&cw, func_a_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_a_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_b_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_b_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_c_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_c_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

STALKER_TESTCASE (call_followed_by_junk)
{
  const guint8 code[] =
  {
    0xe8, 0x05, 0x00, 0x00, 0x00, /* call func         */
    0xff, 0xff, 0xff, 0xff, 0xff, /* <junk>            */
    0x58,                         /* pop eax           */
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0x58,                         /* pop eax           */
    0xc3                          /* ret               */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

typedef struct _CallTemplate CallTemplate;

struct _CallTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint call_site_offset;
  guint target_mov_offset;
  guint target_address_offset;
  gboolean target_address_offset_points_directly_to_function;
  guint target_func_offset;
  gint target_func_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
  gboolean enable_probe;
};

static void probe_template_func_invocation (GumCallSite * site,
    gpointer user_data);

static StalkerTestFunc
invoke_call_from_template (TestStalkerFixture * fixture,
                           const CallTemplate * call_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_func_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;
  GumProbeId probe_id;

  code = test_stalker_fixture_dup_code (fixture,
      call_template->code_template, call_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  target_func_address = code + call_template->target_func_offset;
  if (call_template->target_address_offset_points_directly_to_function)
    target_actual_address = GPOINTER_TO_SIZE (target_func_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_func_address);
  *((gsize *) (code + call_template->target_address_offset)) =
      target_actual_address + call_template->target_func_immediate_fixup;

#if GLIB_SIZEOF_VOID_P == 8
  if (call_template->target_mov_offset != 0)
    *(code + call_template->target_mov_offset - 1) = 0x48;
#endif

  expected_insn_count = INVOKER_INSN_COUNT + call_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += call_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  gum_fake_event_sink_reset (fixture->sink);

  fixture->sink->mask = GUM_CALL;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2 + 1);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->location,
      ==, code + call_template->call_site_offset);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->target,
      ==, code + call_template->target_func_offset);

  probe_id = gum_stalker_add_call_probe (fixture->stalker, target_func_address,
      probe_template_func_invocation, NULL, NULL);
  fixture->sink->mask = GUM_NOTHING;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, == , 1337);
  gum_stalker_remove_call_probe (fixture->stalker, probe_id);

  return func;
}

static void
probe_template_func_invocation (GumCallSite * site,
                                gpointer user_data)
{
}

STALKER_TESTCASE (indirect_call_with_immediate)
{
  const guint8 code[] = {
      0xeb, 0x08,                         /* jmp +8          */

      0x00, 0x00, 0x00, 0x00,             /* address padding */
      0x00, 0x00, 0x00, 0x00,

      0xff, 0x15, 0xf2, 0xff, 0xff, 0xff, /* call            */
      0xc3,                               /* ret             */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
      0xc3,                               /* ret             */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_address_offset = 12;
  call_template.target_func_offset = 17;
  call_template.instruction_count = 5;

#if GLIB_SIZEOF_VOID_P == 8
  call_template.target_address_offset -= 10;
  call_template.target_address_offset_points_directly_to_function = TRUE;
#endif

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_no_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x10,                         /* call [xax]           */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_positive_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x50, 0x54,                   /* call [xax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_negative_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xbd, 0x00, 0x00, 0x00, 0x00, /* mov xbp, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x55, 0xe4,                   /* call [xbp - 0x1c]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate_fixup = 0x1c;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_positive_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x90, 0x54, 0x00, 0x00, 0x00, /* call [xax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_negative_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x90, 0xbe, 0xab, 0xff, 0xff, /* call [xax - 0x5442]  */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = 0x5442;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

STALKER_TESTCASE (indirect_call_with_extended_registers_and_immediate)
{
  const guint8 code[] = {
      0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, /* mov r11, X                   */
                  0x00, 0x00, 0x00, 0x00,
      0x49, 0xba, 0x39, 0x05, 0x00, 0x00, /* mov r10, 1337                */
                  0x00, 0x00, 0x00, 0x00,
      0x43, 0xff, 0x94, 0xd3,             /* call [r11 + r10*8 + 0x270e0] */
                  0xe0, 0x70, 0x02, 0x00,
      0xc3,                               /* ret                          */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337                */
      0xc3,                               /* ret                          */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 20;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 29;
  call_template.target_func_immediate_fixup = -((1337 * 8) + 0x270e0);
  call_template.instruction_count = 6;

  invoke_call_from_template (fixture, &call_template);
}

#endif

STALKER_TESTCASE (indirect_call_with_esp_and_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0x50,                               /* push xax            */
      0x56,                               /* push xsi            */
      0x57,                               /* push xdi            */
      0xff, 0x54, 0x24,                   /* call [xsp + Y]      */
            2 * sizeof (gpointer),
      0x5F,                               /* pop xdi             */
      0x5E,                               /* pop xsi             */
      0x59,                               /* pop xcx             */
      0xc3,                               /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337       */
      0xc3,                               /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 21;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_esp_and_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00,         /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0x50,                                       /* push xax            */
      0x56,                                       /* push xsi            */
      0x57,                                       /* push xdi            */
      0xff, 0x94, 0x24,                           /* call [xsp + Y]      */
            2 * sizeof (gpointer), 0x00, 0x00, 0x00,
      0x5F,                                       /* pop xdi             */
      0x5E,                                       /* pop xsi             */
      0x59,                                       /* pop xcx             */
      0xc3,                                       /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,               /* mov eax, 1337       */
      0xc3,                                       /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 24;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (direct_call_with_register)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0xd0,                         /* call xax             */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3                                /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

STALKER_TESTCASE (direct_call_with_extended_register)
{
  const guint8 code[] = {
      0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, /* mov r9, X            */
                  0x00, 0x00, 0x00, 0x00,
      0x41, 0xff, 0xd1,                   /* call r9              */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 0;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 14;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 0;

  invoke_call_from_template (fixture, &call_template);
}

#endif

STALKER_TESTCASE (popcnt)
{
  const guint8 code[] =
  {
    0xf3, 0x0f, 0xb8, 0xcb, /* popcnt ecx, ebx */
    0xc3,                   /* ret             */
    0xcc,                   /* int3            */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_NOTHING;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
}

typedef struct _JumpTemplate JumpTemplate;

struct _JumpTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint offset_of_target_pointer;
  gboolean offset_of_target_pointer_points_directly;
  guint offset_of_target;
  gint target_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
};

static StalkerTestFunc
invoke_jump (TestStalkerFixture * fixture,
             JumpTemplate * jump_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture, jump_template->code_template,
      jump_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  target_address = code + jump_template->offset_of_target;
  if (jump_template->offset_of_target_pointer_points_directly)
    target_actual_address = GPOINTER_TO_SIZE (target_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_address);
  *((gsize *) (code + jump_template->offset_of_target_pointer)) =
      target_actual_address + jump_template->target_immediate_fixup;

  expected_insn_count = INVOKER_INSN_COUNT + jump_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += jump_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  return func;
}

STALKER_TESTCASE (indirect_jump_with_immediate)
{
  const guint8 code[] = {
      0xeb, 0x08,                         /* jmp +8          */

      0x00, 0x00, 0x00, 0x00,             /* address padding */
      0x00, 0x00, 0x00, 0x00,

      0xff, 0x25, 0xf2, 0xff, 0xff, 0xff, /* jmp             */
      0xcc,                               /* int3            */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
      0xc3,                               /* ret             */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 12;
  jump_template.offset_of_target = 17;
  jump_template.instruction_count = 4;

#if GLIB_SIZEOF_VOID_P == 8
  jump_template.offset_of_target_pointer -= 10;
  jump_template.offset_of_target_pointer_points_directly = TRUE;
#endif

  invoke_jump (fixture, &jump_template);
}

STALKER_TESTCASE (indirect_jump_with_immediate_and_scaled_register)
{
  guint8 code[] = {
      0x90, 0xbe, 0x00, 0x00, 0x00, 0x00,       /* mov xsi, addr                    */
                  0x90, 0x90, 0x90, 0x90,
      0x90, 0xb8, 0x03, 0x00, 0x00, 0x00,       /* mov xax, 3                       */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x64, 0x86, 0xf9,                   /* jmp [xsi + xax * 4 - 7]          */
      0xcc,                                     /* int3                             */

      0xb8, 0x39, 0x05, 0x00, 0x00,             /* mov eax, 1337                    */
      0xc3,                                     /* ret                              */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 2;
  jump_template.offset_of_target = 25;
  jump_template.target_immediate_fixup = -5;
  jump_template.instruction_count = 5;
  jump_template.ia32_padding_instruction_count = 10;

#if GLIB_SIZEOF_VOID_P == 8
  code[0] = 0x48;

  code[10] = 0x48;
  memset (code + 10 + 6, 0, 4);

  jump_template.ia32_padding_instruction_count = 5;
#endif

  invoke_jump (fixture, &jump_template);
}

#if GLIB_SIZEOF_VOID_P == 4

typedef void (* ClobberFunc) (GumCpuContext * ctx);

STALKER_TESTCASE (no_register_clobber)
{
  guint8 * code;
  GumX86Writer cw;
  const gchar * my_func_lbl = "my_func";
  const gchar * my_beach_lbl = "my_beach";
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_pushax (&cw);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->sink);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->transformer);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_follow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EAX, 0xcafebabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_ECX, 0xbeefbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EDX, 0xb00bbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EBX, 0xf001babe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EBP, 0xababe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_ESI, 0x1337);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EDI, 0x1227);

  gum_x86_writer_put_call_near_label (&cw, my_func_lbl);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_ESP, 2 * sizeof (gpointer));
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_unfollow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_push_reg (&cw, GUM_REG_ECX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ESP, sizeof (gpointer) + (8 * sizeof (gpointer))
      + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax), GUM_REG_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx), GUM_REG_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx), GUM_REG_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp), GUM_REG_EBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi), GUM_REG_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi), GUM_REG_EDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx), GUM_REG_EAX);

  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, my_func_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_jmp_short_label (&cw, my_beach_lbl);
  gum_x86_writer_put_breakpoint (&cw);

  gum_x86_writer_put_label (&cw, my_beach_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
  func (&ctx);

  g_assert_cmphex (ctx.eax, ==, 0xcafebabe);
  g_assert_cmphex (ctx.ecx, ==, 0xbeefbabe);
  g_assert_cmphex (ctx.edx, ==, 0xb00bbabe);
  g_assert_cmphex (ctx.ebx, ==, 0xf001babe);
  g_assert_cmphex (ctx.ebp, ==, 0xababe);
  g_assert_cmphex (ctx.esi, ==, 0x1337);
  g_assert_cmphex (ctx.edi, ==, 0x1227);

  gum_free_pages (code);
}

#endif

STALKER_TESTCASE (no_red_zone_clobber)
{
  guint8 code_template[] =
  {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, <addr>    */
                0x90, 0x90, 0x90, 0x90,
    0x90, 0x89, 0x44, 0x24, 0xf8,       /* mov [rsp - 8], xax */
    0x90, 0x8b, 0x44, 0x24, 0xf8,       /* mov xax, [rsp - 8] */
    0xff, 0xe0,                         /* jmp rax            */
    0xcc,                               /* int3               */
    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov rax, 1337      */
    0xc3                                /* ret                */
  };
  guint8 * code;
  StalkerTestFunc func;
  gint ret;

#if GLIB_SIZEOF_VOID_P == 8
  code_template[0] = 0x48;
  code_template[10] = 0x48;
  code_template[15] = 0x48;
#endif

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  *((gpointer *) (code + 2)) = code + 23;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  ret = func (42);
  g_assert_cmpint (ret, ==, 1337);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
#if GLIB_SIZEOF_VOID_P == 8
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);
#else
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 13);
#endif
  g_assert_cmpint (ret, ==, 1337);
}

STALKER_TESTCASE (big_block)
{
  const guint nop_instruction_count = 1000000;
  guint8 * code;
  GumX86Writer cw;
  guint i;
  StalkerTestFunc func;

  code = gum_alloc_n_pages (
      (nop_instruction_count / gum_query_page_size ()) + 1,
      GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, code);

  for (i = 0; i != nop_instruction_count; i++)
    gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code,
          gum_x86_writer_offset (&cw)));

  gum_x86_writer_clear (&cw);
  gum_free_pages (code);

  test_stalker_fixture_follow_and_invoke (fixture, func, -1);
}

#ifdef G_OS_WIN32

typedef struct _TestWindow TestWindow;

typedef void (* TestWindowMessageHandler) (TestWindow * window, gpointer user_data);

struct _TestWindow
{
  LPTSTR klass;
  HWND handle;
  GumStalker * stalker;

  TestWindowMessageHandler handler;
  gpointer user_data;
};

static void do_follow (TestWindow * window, gpointer user_data);
static void do_unfollow (TestWindow * window, gpointer user_data);

static TestWindow * create_test_window (GumStalker * stalker);
static void destroy_test_window (TestWindow * window);
static void send_message_and_pump_messages_briefly (TestWindow * window,
    TestWindowMessageHandler handler, gpointer user_data);

static LRESULT CALLBACK test_window_proc (HWND hwnd, UINT msg,
    WPARAM wparam, LPARAM lparam);

#if GLIB_SIZEOF_VOID_P == 4

static StalkerTestFunc
invoke_indirect_call_seg (TestStalkerFixture * fixture,
                          GumEventType mask)
{
  const guint8 code_template[] = {
      0x64, 0xff, 0x35, 0x00, 0x07, 0x00, 0x00, /* push dword [dword fs:0x700] */
                                                /* mov dword [dword fs:0x700], <addr> */
      0x64, 0xc7, 0x05, 0x00, 0x07, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,

      0x64, 0xff, 0x15, 0x00, 0x07, 0x00, 0x00, /* call fs:700h                */

      0x50,                                     /* push eax                    */
      0x8b, 0x44, 0x24, 0x04,                   /* mov eax, [esp+0x4]          */
      0x64, 0xa3, 0x00, 0x07, 0x00, 0x00,       /* mov [fs:0x700],eax          */
      0x58,                                     /* pop eax                     */
      0x81, 0xc4, 0x04, 0x00, 0x00, 0x00,       /* add esp, 0x4                */

      0xc3,                                     /* ret                         */

      0xb8, 0xbe, 0xba, 0xfe, 0xca,             /* mov eax, 0xcafebabe         */
      0xc3,                                     /* ret                         */
  };
  guint8 * code;
  StalkerTestFunc func;
  guint ret;

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  *((gpointer *) (code + 14)) = code + sizeof (code_template) - 1 - 5;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmphex (ret, ==, 0xcafebabe);

  return func;
}

STALKER_TESTCASE (win32_indirect_call_seg)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  invoke_indirect_call_seg (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 11);
}

#endif

STALKER_TESTCASE (win32_messagebeep_api)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  MessageBeep (MB_ICONINFORMATION);
  gum_stalker_unfollow_me (fixture->stalker);
}

STALKER_TESTCASE (win32_follow_user_to_kernel_to_callback)
{
  TestWindow * window;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  window = create_test_window (fixture->stalker);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  send_message_and_pump_messages_briefly (window, do_unfollow,
      fixture->stalker);
  g_assert (!gum_stalker_is_following_me (fixture->stalker));

  destroy_test_window (window);
}

STALKER_TESTCASE (win32_follow_callback_to_kernel_to_user)
{
  TestWindow * window;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  window = create_test_window (fixture->stalker);

  send_message_and_pump_messages_briefly (window, do_follow, fixture->sink);
  g_assert (gum_stalker_is_following_me (fixture->stalker));
  gum_stalker_unfollow_me (fixture->stalker);

  destroy_test_window (window);
}

static void
do_follow (TestWindow * window, gpointer user_data)
{
  gum_stalker_follow_me (window->stalker, NULL, GUM_EVENT_SINK (user_data));
}

static void
do_unfollow (TestWindow * window, gpointer user_data)
{
  gum_stalker_unfollow_me (window->stalker);
}

static TestWindow *
create_test_window (GumStalker * stalker)
{
  TestWindow * window;
  WNDCLASS wc = { 0, };

  window = g_slice_new (TestWindow);

  window->stalker = stalker;

  wc.lpfnWndProc = test_window_proc;
  wc.hInstance = GetModuleHandle (NULL);
  wc.lpszClassName = _T ("GumTestWindowClass");
  window->klass = (LPTSTR) GSIZE_TO_POINTER (RegisterClass (&wc));
  g_assert (window->klass != 0);

#pragma warning (push)
#pragma warning (disable: 4306)
  window->handle = CreateWindow (window->klass, _T ("GumTestWindow"),
      WS_CAPTION, 10, 10, 320, 240, HWND_MESSAGE, NULL,
      GetModuleHandle (NULL), NULL);
#pragma warning (pop)
  g_assert (window->handle != NULL);

  SetWindowLongPtr (window->handle, GWLP_USERDATA, (LONG_PTR) window);
  ShowWindow (window->handle, SW_SHOWNORMAL);

  return window;
}

static void
destroy_test_window (TestWindow * window)
{
  g_assert (UnregisterClass (window->klass, GetModuleHandle (NULL)));

  g_slice_free (TestWindow, window);
}

static void
send_message_and_pump_messages_briefly (TestWindow * window,
    TestWindowMessageHandler handler, gpointer user_data)
{
  MSG msg;

  window->handler = handler;
  window->user_data = user_data;

  SendMessage (window->handle, WM_USER, 0, 0);

  while (GetMessage (&msg, NULL, 0, 0))
  {
    TranslateMessage (&msg);
    DispatchMessage (&msg);
  }
}

static LRESULT CALLBACK
test_window_proc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  if (msg == WM_USER)
  {
    TestWindow * window;

    window = (TestWindow *) GetWindowLongPtr (hwnd, GWLP_USERDATA);
    window->handler (window, window->user_data);

    SetTimer (hwnd, 1, USER_TIMER_MINIMUM, NULL);

    return 0;
  }
  else if (msg == WM_TIMER)
  {
    KillTimer (hwnd, 1);
    DestroyWindow (hwnd);
  }
  else if (msg == WM_DESTROY)
  {
    PostQuitMessage (0);
    return 0;
  }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

#endif
