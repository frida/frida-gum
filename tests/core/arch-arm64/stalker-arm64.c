/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm64-fixture.c"

TEST_LIST_BEGIN (stalker)

  /* EVENTS */
  STALKER_TESTENTRY (no_events)
  STALKER_TESTENTRY (call)
  STALKER_TESTENTRY (ret)
  STALKER_TESTENTRY (exec)

  /* BRANCH */
  STALKER_TESTENTRY (unconditional_branch)
  STALKER_TESTENTRY (unconditional_branch_reg)
  STALKER_TESTENTRY (conditional_branch)
  STALKER_TESTENTRY (compare_and_branch)
  STALKER_TESTENTRY (test_bit_and_branch)

  /* FOLLOWS */
  STALKER_TESTENTRY (follow_std_call)
  STALKER_TESTENTRY (follow_return)
  STALKER_TESTENTRY (follow_syscall)
  STALKER_TESTENTRY (follow_thread)

  /* EXTRA */
  STALKER_TESTENTRY (heap_api)
  STALKER_TESTENTRY (no_register_clobber)
  STALKER_TESTENTRY (performance)

TEST_LIST_END ()

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

static const guint32 flat_code[] = {
  0xCB000000, /* SUB W0, W0, W0 */
  0x91000400, /* ADD W0, W0, #1 */
  0x91000400, /* ADD W0, W0, #1 */
  0xd65f03c0  /* RET            */
};

static StalkerTestFunc
invoke_flat (TestArm64StalkerFixture * fixture,
             GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_arm64_stalker_fixture_dup_code (fixture, flat_code,
      sizeof (flat_code)));

  fixture->sink->mask = mask;
  ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 2);

  return func;
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
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);
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
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;

  GUM_ASSERT_CMPADDR (ev->location, ==, ((guint8 *) GSIZE_TO_POINTER (
      func)) + 3 * 4);
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
  ev =
      &g_array_index (fixture->sink->events, GumEvent, INVOKER_IMPL_OFFSET).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);
}

STALKER_TESTCASE (unconditional_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_b_imm (&cw, address);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 13);

  gum_free_pages (code);
}

STALKER_TESTCASE (unconditional_branch_reg)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  arm64_reg reg = ARM64_REG_X13;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);
  if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30)
    gum_arm64_writer_put_pop_reg_reg (&cw, reg, ARM64_REG_XZR);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30)
    gum_arm64_writer_put_push_reg_reg (&cw, reg, reg);
  gum_arm64_writer_put_ldr_reg_address (&cw, reg, address);
  gum_arm64_writer_put_br_reg (&cw, reg);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 13);

  gum_free_pages (code);
}

STALKER_TESTCASE (conditional_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  arm64_cc cc = ARM64_CC_EQ;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_instruction (&cw, 0xF1000800);  /* SUBS X0, X0, #2 */
  gum_arm64_writer_put_b_cond_label (&cw, cc, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_b_imm (&cw, address);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

STALKER_TESTCASE (compare_and_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  const gchar * my_ken_lbl = "my_ken";
  const gchar * my_nken_lbl = "my_nken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_sub_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
  gum_arm64_writer_put_cbz_reg_label (&cw, ARM64_REG_X0, my_ken_lbl);

  gum_arm64_writer_put_label (&cw, my_nken_lbl);
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_X0, my_nken_lbl);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

STALKER_TESTCASE (test_bit_and_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  const gchar * my_ken_lbl = "my_ken";
  const gchar * my_nken_lbl = "my_nken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_sub_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
  gum_arm64_writer_put_tbz_reg_imm_label (&cw, ARM64_REG_W0, 0, my_ken_lbl);

  gum_arm64_writer_put_label (&cw, my_nken_lbl);
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_tbnz_reg_imm_label (&cw, ARM64_REG_W0, 0, my_nken_lbl);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

STALKER_TESTCASE (follow_std_call)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_SP);

  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_bl_imm (&cw, address);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 4);

  gum_free_pages (code);
}

STALKER_TESTCASE (follow_return)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_SP);

  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  /*
   * alternative for instruction RET X15
   * gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X15, ARM64_REG_X30);
   * gum_arm64_writer_put_instruction (&cw, 0xD65F01E0);
   */
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_bl_imm (&cw, address);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  r = func (2);

  g_assert_cmpint (r, ==, 4);

  gum_free_pages (code);
}

STALKER_TESTCASE (follow_syscall)
{
  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
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

STALKER_TESTCASE (follow_thread)
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

STALKER_TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

typedef void (* ClobberFunc) (GumCpuContext * ctx);

STALKER_TESTCASE (no_register_clobber)
{
  guint8 * code;
  GumArm64Writer cw;
  gint i;
  gint offset;
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    gum_arm64_writer_put_ldr_reg_u64 (&cw, i, i);
  }

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  offset = (4 * sizeof (gpointer)) + (32 * sizeof (gpointer));

  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    gum_arm64_writer_put_str_reg_reg_offset (&cw, i, ARM64_REG_SP,
        offset + G_STRUCT_OFFSET (GumCpuContext, x[i - ARM64_REG_X0]));
  }

  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
  func (&ctx);

  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    g_assert_cmphex (ctx.x[i - ARM64_REG_X0], ==, i);
  }

  gum_free_pages (code);
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

STALKER_TESTCASE (performance)
{
  GTimer * timer;
  gdouble duration_direct, duration_stalked;

  timer = g_timer_new ();
  pretend_workload ();

  g_timer_reset (timer);
  pretend_workload ();
  duration_direct = g_timer_elapsed (timer, NULL);

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));

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

  g_print ("\n\t<duration_direct=%f duration_stalked=%f ratio=%f>\n",
      duration_direct, duration_stalked, duration_stalked / duration_direct);
}
