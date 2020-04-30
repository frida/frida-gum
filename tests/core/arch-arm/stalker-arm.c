/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

#include <lzma.h>
#ifdef HAVE_LINUX
# include <sys/prctl.h>
#endif

static void duplicate_adds (GumStalkerIterator * iterator,
    GumStalkerWriter * output, gpointer user_data);

static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerWriter * output, gpointer user_data);

static gpointer run_stalked_briefly (gpointer data);

static gpointer run_stalked_into_termination (gpointer data);

static gpointer increment_integer (gpointer data);

TESTLIST_BEGIN (stalker)
  TESTENTRY (trust_is_zero)
  TESTENTRY (trust_unsupported)
  TESTENTRY (add_call_probe_unsupported)
  TESTENTRY (remove_call_probe_unsupported)
  TESTENTRY (compile_events_unsupported)

  TESTENTRY (arm_flat_code)
  TESTENTRY (thumb_flat_code)
  TESTENTRY (arm_no_events)
  TESTENTRY (thumb_no_events)
  TESTENTRY (arm_exec_events_generated)
  TESTENTRY (thumb_exec_events_generated)
  TESTENTRY (arm_call_events_generated)
  TESTENTRY (thumb_call_events_generated)
  TESTENTRY (arm_block_events_generated)
  TESTENTRY (thumb_block_events_generated)
  TESTENTRY (arm_nested_call_events_generated)
  TESTENTRY (thumb_nested_call_events_generated)
  TESTENTRY (arm_nested_ret_events_generated)
  TESTENTRY (thumb_nested_ret_events_generated)
  TESTENTRY (arm_unmodified_lr)
  TESTENTRY (thumb_unmodified_lr)
  TESTENTRY (arm_excluded_range)
  TESTENTRY (thumb_excluded_range)
  TESTENTRY (arm_excluded_range_call_events)
  TESTENTRY (thumb_excluded_range_call_events)
  TESTENTRY (arm_excluded_range_ret_events)
  TESTENTRY (thumb_excluded_range_ret_events)
  TESTENTRY (arm_pop_pc_ret_events_generated)
  TESTENTRY (thumb_pop_pc_ret_events_generated)
  TESTENTRY (arm_pop_just_pc_ret_events_generated)
  TESTENTRY (thumb_pop_just_pc_ret_events_generated)
  TESTENTRY (arm_ldm_pc_ret_events_generated)
  TESTENTRY (thumb_ldm_pc_ret_events_generated)
  TESTENTRY (arm_branch_cc_block_events_generated)
  TESTENTRY (thumb_branch_cc_block_events_generated)

  TESTENTRY (thumb_cbz_cbnz_block_events_generated)

  /*
   * The following tests have not thumb equivalent as thumb does not support
   * conditional instructions nor is pc allowed as the destination register for
   * some op-codes.
   */
  TESTENTRY (arm_branch_link_cc_block_events_generated)
  TESTENTRY (arm_cc_excluded_range)
  TESTENTRY (arm_ldr_pc)
  TESTENTRY (arm_ldr_pc_pre_index_imm)
  TESTENTRY (arm_ldr_pc_post_index_imm)
  TESTENTRY (arm_ldr_pc_pre_index_imm_negative)
  TESTENTRY (arm_ldr_pc_post_index_imm_negative)
  TESTENTRY (arm_sub_pc)
  TESTENTRY (arm_add_pc)

  TESTENTRY (call_thumb)
  TESTENTRY (branch_thumb)
  TESTENTRY (can_follow_workload)
  TESTENTRY (performance)

  TESTENTRY (custom_transformer)
  TESTENTRY (unfollow_should_be_allowed_before_first_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_first_transform)
  TESTENTRY (unfollow_should_be_allowed_after_first_transform)
  TESTENTRY (unfollow_should_be_allowed_before_second_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_second_transform)
  TESTENTRY (unfollow_should_be_allowed_after_second_transform)

  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
  TESTENTRY (unfollow_should_handle_terminated_thread)
  TESTENTRY (pthread_create)
  TESTENTRY (heap_api)
TESTLIST_END ()

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

TESTCASE (trust_is_zero)
{
  gint threshold = gum_stalker_get_trust_threshold (fixture->stalker);
  g_assert_cmpuint (threshold, ==, 0);
}

TESTCASE (trust_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Trust threshold unsupported");

  gum_stalker_set_trust_threshold (fixture->stalker, 10);
  g_test_assert_expected_messages ();
}

TESTCASE (deactivate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");

  gum_stalker_deactivate (fixture->stalker);
  g_test_assert_expected_messages ();
}

TESTCASE (activate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");

  gum_stalker_activate (fixture->stalker, NULL);
  g_test_assert_expected_messages ();
}

TESTCASE (add_call_probe_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Call probes unsupported");

  GumProbeId id = gum_stalker_add_call_probe (fixture->stalker, NULL,
      dummyCallProbe, NULL, dummyDestroyNotify);

  g_test_assert_expected_messages ();
  g_assert_cmpuint (id, ==, 0);
}

TESTCASE (remove_call_probe_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Call probes unsupported");

  gum_stalker_remove_call_probe (fixture->stalker, 10);
  g_test_assert_expected_messages ();
}

TESTCASE (compile_events_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Compile events unsupported");

  invoke_arm_flat_expecting_return_value (fixture, GUM_COMPILE, 2);
  g_test_assert_expected_messages ();
}

TESTCASE (arm_flat_code)
{
  g_assert_cmpuint (CODE_SIZE (arm_flat_code), ==, 16);

  guint * code = (guint *) CODE_START (arm_flat_code);
  g_assert_cmpuint (code[0], ==, 0xe0400000);
  g_assert_cmpuint (code[1], ==, 0xe2800001);
  g_assert_cmpuint (code[2], ==, 0xe2800001);
  g_assert_cmpuint (code[3], ==, 0xe1a0f00e);
}

TESTCASE (thumb_flat_code)
{
  g_assert_cmpuint (CODE_SIZE (thumb_flat_code), ==, 10);

  guint16 * code = (guint16 *) CODE_START (thumb_flat_code);
  g_assert_cmpuint (code[0], ==, 0xb500);
  g_assert_cmpuint (code[1], ==, 0x1a00);
  g_assert_cmpuint (code[2], ==, 0x3001);
  g_assert_cmpuint (code[3], ==, 0x3001);
  g_assert_cmpuint (code[4], ==, 0xbd00);
}

TESTCASE (arm_no_events)
{
  invoke_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (thumb_no_events)
{
  invoke_thumb_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (arm_exec_events_generated)
{
  GumAddress func;

  func = invoke_arm_flat_expecting_return_value (fixture, GUM_EXEC, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==,
     INVOKER_INSN_COUNT + (CODE_SIZE (arm_flat_code) / 4));

  GUM_ASSERT_EVENT_ADDR(exec, 0, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET);

  GUM_ASSERT_EVENT_ADDR(exec, 1, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR(exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR(exec, 3, location, func + 4);
  GUM_ASSERT_EVENT_ADDR(exec, 4, location, func + 8);
  GUM_ASSERT_EVENT_ADDR(exec, 5, location, func + 12);

  GUM_ASSERT_EVENT_ADDR(exec, 6, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 8);

  GUM_ASSERT_EVENT_ADDR(exec, 7, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 12);

  GUM_ASSERT_EVENT_ADDR(exec, 8, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 16);

  GUM_ASSERT_EVENT_ADDR(exec, 9, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (thumb_exec_events_generated)
{
  GumAddress func;

  func = invoke_thumb_flat_expecting_return_value (fixture, GUM_EXEC, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==,
     INVOKER_INSN_COUNT + (CODE_SIZE (thumb_flat_code) / 2));

  GUM_ASSERT_EVENT_ADDR(exec, 0, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET);

  GUM_ASSERT_EVENT_ADDR(exec, 1, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR(exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR(exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR(exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR(exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR(exec, 6, location, func + 8);

  GUM_ASSERT_EVENT_ADDR(exec, 7, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 8);

  GUM_ASSERT_EVENT_ADDR(exec, 8, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 12);

  GUM_ASSERT_EVENT_ADDR(exec, 9, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 16);

  GUM_ASSERT_EVENT_ADDR(exec, 10, location,
    fixture->stalked_invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (arm_call_events_generated)
{
  GumAddress func = invoke_arm_flat_expecting_return_value (fixture, GUM_CALL,
      2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR(call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR(call, 0, depth, 0);
}

TESTCASE (thumb_call_events_generated)
{
  GumAddress func = invoke_thumb_flat_expecting_return_value (fixture, GUM_CALL,
      2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR(call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR(call, 0, depth, 0);
}

TESTCODE (arm_block_events,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "b 1f \n"
  "udf #0 \n"
  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
  );

TESTCASE (arm_block_events_generated)
{
  GumAddress func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_block_events), CODE_SIZE (arm_block_events), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + (3 * 4));
}

TESTCODE (thumb_block_events,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "b 1f \n"
  "udf #0 \n"
  "1: \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"
  );

TESTCASE (thumb_block_events_generated)
{
  GumAddress func = invoke_thumb_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (thumb_block_events), CODE_SIZE (thumb_block_events), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + (4 * 2));
}

TESTCODE (arm_nested_call,
  ".arm \n"
  "stmdb sp!, {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "bl 3f \n"
  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"

  "2: \n"
  "stmdb sp!, {lr} \n"
  "add r0, r0, #1 \n"
  "bl 3f \n"
  "ldmia sp!, {lr} \n"
  "mov pc, lr \n"

  "3: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
  );

TESTCASE (arm_nested_call_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_CALL,
      CODE_START (arm_nested_call), CODE_SIZE (arm_nested_call), 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR(call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR(call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + (3 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + (7 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + (9 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR(call, 3, location, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 3, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR(call, 3, depth, 1);
}

TESTCODE (thumb_nested_call,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "bl 3f \n"
  "pop {pc} \n"

  "2: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "bl 3f \n"
  "pop {pc} \n"

  "3: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"
  );

TESTCASE (thumb_nested_call_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_CALL,
      CODE_START (thumb_nested_call), CODE_SIZE (thumb_nested_call), 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR(call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR(call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 6);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 17);
  GUM_ASSERT_EVENT_ADDR(call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + 20);
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + 27);
  GUM_ASSERT_EVENT_ADDR(call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR(call, 3, location, func + 10);
  GUM_ASSERT_EVENT_ADDR(call, 3, target, func + 27);
  GUM_ASSERT_EVENT_ADDR(call, 3, depth, 1);
}

TESTCASE (arm_nested_ret_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_RET,
      CODE_START (arm_nested_call), CODE_SIZE (arm_nested_call), 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + (10 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + (11 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 1, target, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 2, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 2, target, func + (5 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 3, location, func + (6 * 4));
  GUM_ASSERT_EVENT_ADDR(ret, 3, depth, 0);
}

TESTCASE (thumb_nested_ret_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_RET,
      CODE_START (thumb_nested_call), CODE_SIZE (thumb_nested_call), 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 30);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 25);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 24);
  GUM_ASSERT_EVENT_ADDR(ret, 1, target, func + 11);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 2, location, func + 30);
  GUM_ASSERT_EVENT_ADDR(ret, 2, target, func + 15);
  GUM_ASSERT_EVENT_ADDR(ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 3, location, func + 14);
  GUM_ASSERT_EVENT_ADDR(ret, 3, depth, 0);
}

TESTCODE (arm_unmodified_lr,
  ".arm \n"
  "stmdb sp!, {lr} \n"
  "bl 1f \n"
  ".word 0xecececec \n"
  "1: \n"
  "ldr r0, [lr] \n"
  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"
);

TESTCASE (arm_unmodified_lr)
{
  invoke_arm_expecting_return_value (fixture, 0, CODE_START (arm_unmodified_lr),
      CODE_SIZE (arm_unmodified_lr), 0xecececec);
}

TESTCODE (thumb_unmodified_lr,
  ".thumb \n"
  "push {lr} \n"
  "bl 1f \n"
  ".word 0xecececec \n"
  "1: \n"
  "sub r1, r1, r1 \n"
  "add r1, r1, #1 \n"
  "mov r0, lr \n"
  "bic r0, r0, r1 \n"
  "ldr r0, [r0] \n"
  "pop {pc} \n"
);

TESTCASE (thumb_unmodified_lr)
{
  invoke_thumb_expecting_return_value (fixture, 0,
      CODE_START (thumb_unmodified_lr),
      CODE_SIZE (thumb_unmodified_lr), 0xecececec);
}

TESTCODE (arm_excluded_range,
  ".arm \n"
  "stmdb sp!, {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_excluded_range)
{
  GumAddress func;

  func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (arm_excluded_range),
      CODE_SIZE (arm_excluded_range));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 24,
    .size = 8
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_EXEC;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func);
  g_assert_cmpuint (ret, ==, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

  GUM_ASSERT_EVENT_ADDR(exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR(exec, 3, location, func + 4);
  GUM_ASSERT_EVENT_ADDR(exec, 4, location, func + 8);
  GUM_ASSERT_EVENT_ADDR(exec, 5, location, func + 12);
  GUM_ASSERT_EVENT_ADDR(exec, 6, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(exec, 7, location, func + 20);
}

TESTCODE (thumb_excluded_range,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "pop {pc} \n"

  "2: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"
);

TESTCASE (thumb_excluded_range)
{
  GumAddress func;

  func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (thumb_excluded_range),
      CODE_SIZE (thumb_excluded_range));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 12,
    .size = 6
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_EXEC;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func + 1);
  g_assert_cmpuint (ret, ==, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

  GUM_ASSERT_EVENT_ADDR(exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR(exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR(exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR(exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR(exec, 6, location, func + 10);
}

TESTCODE (arm_excluded_range_call,
  ".arm \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 3f \n"
  "bl 1f \n"
  "pop {pc} \n"

  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "3: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "bl 2b \n"
  "pop {pc} \n"
);

TESTCASE (arm_excluded_range_call_events)
{
  GumAddress func;

  func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (arm_excluded_range_call),
      CODE_SIZE (arm_excluded_range_call));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 40,
    .size = 16
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_CALL;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 12);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 40);
  GUM_ASSERT_EVENT_ADDR(call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + 24);
  GUM_ASSERT_EVENT_ADDR(call, 2, depth, 1);
}

TESTCODE (thumb_excluded_range_call,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 3f \n"
  "bl 1f \n"
  "pop {pc} \n"

  "1: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"

  "2: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"

  "3: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "bl 2b \n"
  "pop {pc} \n"
);

TESTCASE (thumb_excluded_range_call_events)
{
  GumAddress func;

  func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (thumb_excluded_range_call),
      CODE_SIZE (thumb_excluded_range_call));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 28,
    .size = 10
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_CALL;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func + 1);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 6);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 29);
  GUM_ASSERT_EVENT_ADDR(call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + 10);
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + 17);
  GUM_ASSERT_EVENT_ADDR(call, 2, depth, 1);
}


TESTCASE (arm_excluded_range_ret_events)
{
  GumAddress func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (arm_excluded_range_call),
      CODE_SIZE (arm_excluded_range_call));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 40,
    .size = 16
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_RET;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 20);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 20);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCASE (thumb_excluded_range_ret_events)
{
  GumAddress func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (thumb_excluded_range_call),
      CODE_SIZE (thumb_excluded_range_call));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 28,
    .size = 10
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_RET;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func + 1);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 20);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 15);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 14);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (arm_pop_pc,
  ".arm \n"
  "stmdb sp!, {r4-r8, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {r4-r8, pc} \n"

  "2: \n"
  "stmdb sp!, {r1-r3, lr} \n"
  "add r0, r0, #1 \n"
  "ldmia sp!, {r1-r3, pc} \n"
);

TESTCASE (arm_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_RET,
      CODE_START (arm_pop_pc), CODE_SIZE (arm_pop_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (thumb_pop_pc,
  ".thumb \n"
  "push {r4-r7, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "pop {r4-r7, pc} \n"

  "2: \n"
  "push {r1-r3, lr} \n"
  "add r0, r0, #1 \n"
  "pop {r1-r3, pc} \n"
);

TESTCASE (thumb_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_RET,
      CODE_START (thumb_pop_pc), CODE_SIZE (thumb_pop_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (arm_pop_just_pc,
  ".arm \n"
  "stmdb sp!, {r4-r8, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {r4-r8, pc} \n"

  "2: \n"
  "stmdb sp!, {lr} \n"
  "add r0, r0, #1 \n"
  "ldmia sp!, {pc} \n"
);

TESTCASE (arm_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_RET,
      CODE_START (arm_pop_just_pc), CODE_SIZE (arm_pop_just_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (thumb_pop_just_pc,
  ".thumb \n"
  "push {r4-r7, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "pop {r4-r7, pc} \n"

  "2: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "pop {pc} \n"
);

TESTCASE (thumb_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_RET,
      CODE_START (thumb_pop_just_pc), CODE_SIZE (thumb_pop_just_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}


TESTCODE (arm_ldm_pc,
  ".arm \n"
  "stmdb sp!, {r4-r8, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {r4-r8, pc} \n"

  "2: \n"
  "add r3, sp, #0 \n"
  "stmdb r3!, {r4-r8, lr} \n"
  "add r0, r0, #1 \n"
  "ldmia r3!, {r4-r8, pc} \n"
);

TESTCASE (arm_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_RET,
      CODE_START (arm_ldm_pc), CODE_SIZE (arm_ldm_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 32);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (thumb_ldm_pc,
  ".thumb \n"
  "push {r4-r7, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "pop {r4-r7, pc} \n"

  "2: \n"
  "add r3, sp, #0 \n"
  ".word 0x4006e923  // stmdb r3!, {r0-r2, lr} \n"
  "add r0, r0, #1 \n"
  ".word 0x8006e8b3 // ldmia r3!, {r0-r2, pc} \n"
);

TESTCASE (thumb_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_RET,
      CODE_START (thumb_ldm_pc), CODE_SIZE (thumb_ldm_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR(ret, 0, location, func + 20);
  GUM_ASSERT_EVENT_ADDR(ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR(ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR(ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR(ret, 1, depth, 0);
}

TESTCODE (arm_b_cc,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "sub r1, r1, r1 \n"

  "cmp r1, #0 \n"
  "beq 1f \n"
  "add r0, r0, #1 \n"
  "1: \n"

  "cmp r1, #1 \n"
  "beq 2f \n"
  "add r0, r0, #2 \n"
  "2: \n"

  "cmp r1, #0 \n"
  "bge 3f \n"
  "add r0, r0, #4 \n"
  "3: \n"

  "cmp r1, #0 \n"
  "blt 4f \n"
  "add r0, r0, #8 \n"
  "4: \n"

  "mov pc, lr \n"
);

TESTCASE (arm_branch_cc_block_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START    (arm_b_cc), CODE_SIZE (arm_b_cc), 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 16);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 20);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 28);

  GUM_ASSERT_EVENT_ADDR(block, 2, begin, func + 28);
  GUM_ASSERT_EVENT_ADDR(block, 2, end, func + 40);

  GUM_ASSERT_EVENT_ADDR(block, 3, begin, func + 44);
  GUM_ASSERT_EVENT_ADDR(block, 3, end, func + 52);
}

TESTCODE (thumb_b_cc,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "sub r1, r1, r1 \n"

  "cmp r1, #0 \n"
  "beq 1f \n"
  "add r0, r0, #1 \n"
  "1: \n"

  "cmp r1, #1 \n"
  "beq 2f \n"
  "add r0, r0, #2 \n"
  "2: \n"

  "cmp r1, #0 \n"
  "bge 3f \n"
  "add r0, r0, #4 \n"
  "3: \n"

  "cmp r1, #0 \n"
  "blt 4f \n"
  "add r0, r0, #8 \n"
  "4: \n"

  "pop {pc} \n"
);

TESTCASE (thumb_branch_cc_block_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START    (thumb_b_cc), CODE_SIZE (thumb_b_cc), 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 10);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 12);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 16);

  GUM_ASSERT_EVENT_ADDR(block, 2, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR(block, 2, end, func + 22);

  GUM_ASSERT_EVENT_ADDR(block, 3, begin, func + 24);
  GUM_ASSERT_EVENT_ADDR(block, 3, end, func + 28);
}

TESTCODE (thumb_cbz_cbnz,
  ".thumb \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "sub r1, r1, r1 \n"
  "sub r2, r2, r2 \n"
  "add r2, r2, #1 \n"

  ".short 0xb101 // cbz r1, 1f \n"
  "add r0, r0, #1 \n"
  "1: \n"

  ".short 0xb901 // cbnz r1, 2f \n"
  "add r0, r0, #2 \n"
  "2: \n"

  ".short 0xb102 // cbz r2, 3f \n"
  "add r0, r0, #4 \n"
  "3: \n"

  ".short 0xb902 // cbnz r2, 4f \n"
  "add r0, r0, #8 \n"
  "4: \n"

  "pop {pc} \n"
);

TESTCASE (thumb_cbz_cbnz_block_events_generated)
{
  GumAddress func;

  func = invoke_thumb_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (thumb_cbz_cbnz), CODE_SIZE (thumb_cbz_cbnz), 6);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 12);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 14);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 16);

  GUM_ASSERT_EVENT_ADDR(block, 2, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR(block, 2, end, func + 20);

  GUM_ASSERT_EVENT_ADDR(block, 3, begin, func + 20);
  GUM_ASSERT_EVENT_ADDR(block, 3, end, func + 24);
}

TESTCODE (arm_bl_cc,
  ".arm \n"
  "push {lr} \n"

  "sub r0, r0, r0 \n"
  "sub r1, r1, r1 \n"

  "cmp r1, #0 \n"
  "bleq 1f \n"

  "cmp r1, #1 \n"
  "bleq 2f \n"

  "cmp r1, #0 \n"
  "blge 3f \n"

  "cmp r1, #0 \n"
  "bllt 4f \n"

  "pop {pc} \n"

  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #2 \n"
  "mov pc, lr \n"

  "3: \n"
  "add r0, r0, #4 \n"
  "mov pc, lr \n"

  "4: \n"
  "add r0, r0, #8 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_branch_link_cc_block_events_generated)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_CALL,
      CODE_START (arm_bl_cc), CODE_SIZE (arm_bl_cc), 5);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 48);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + 32);
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + 64);
}

TESTCODE (arm_cc_excluded_range,
  ".arm \n"
  "stmdb sp!, {lr} \n"
  "sub r0, r0, r0 \n"
  "sub r1, r1, r1 \n"

  "cmp r1, #0 \n"
  "bleq 1f \n"

  "cmp r1, #0 \n"
  "blne 2f \n"

  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"

  "1: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "bl 3f \n"
  "pop {pc} \n"

  "2: \n"
  "push {lr} \n"
  "add r0, r0, #2 \n"
  "bl 3f \n"
  "pop {pc} \n"

  "3: \n"
  "mov pc, lr \n"
);

TESTCASE (arm_cc_excluded_range)
{
  GumAddress func;

  func = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (arm_cc_excluded_range),
      CODE_SIZE (arm_cc_excluded_range));

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 36,
    .size = 36
  };

  gum_stalker_exclude (fixture->stalker, &r);

  fixture->sink->mask = GUM_CALL;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func);
  g_assert_cmpuint (ret, ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 36);
}

static gboolean
store_range_of_test_runner (const GumModuleDetails * details,
                            gpointer user_data)
{
  GumMemoryRange * runner_range = user_data;

  if (strstr (details->name, "gum-tests") != NULL)
  {
    *runner_range = *details->range;
    return FALSE;
  }

  return TRUE;
}

TESTCODE (arm_ldr_pc,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "ldr pc, f3 \n"
  "udf #16 \n"
  ".word 0xecececec \n"
  "f3: \n"
  ".word f4 \n"

  "f4: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_ldr_pc)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_ldr_pc), CODE_SIZE (arm_ldr_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 12);
}

TESTCODE (arm_ldr_pc_pre_index_imm,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "adr r1, arm_ldr_pc_pre_index_imm_data \n"
  "ldr pc, [r1, #8]! \n"
  "udf #16 \n"

  "arm_ldr_pc_pre_index_imm_data: \n"
  ".word 0xecececec \n"
  ".word 0xf0f0f0f0 \n"
  ".word arm_ldr_pc_pre_index_imm_func \n"
  ".word 0xbabababa \n"

  "arm_ldr_pc_pre_index_imm_func: \n"
  "ldr r1, [r1, #4] \n"
  "add r0, r0, r1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_ldr_pc_pre_index_imm)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_ldr_pc_pre_index_imm), CODE_SIZE (arm_ldr_pc_pre_index_imm), 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "adr r1, arm_ldr_pc_post_index_imm_data \n"
  "ldr pc, [r1], #8 \n"
  "udf #16 \n"

  "arm_ldr_pc_post_index_imm_data: \n"
  ".word arm_ldr_pc_post_index_imm_func \n"
  ".word 0xf0f0f0f0 \n"
  ".word 0xbabababa \n"

  "arm_ldr_pc_post_index_imm_func: \n"
  "ldr r1, [r1, #0] \n"
  "add r0, r0, r1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_ldr_pc_post_index_imm)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_ldr_pc_post_index_imm), CODE_SIZE (arm_ldr_pc_post_index_imm), 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_pre_index_imm_negative,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "adr r1, arm_ldr_pc_pre_index_imm_negative_data \n"
  "ldr pc, [r1, #-8]! \n"
  "udf #16 \n"

  ".word arm_ldr_pc_pre_index_imm_negative_func \n"
  ".word 0xecececec \n"
  "arm_ldr_pc_pre_index_imm_negative_data: \n"
  ".word 0xf0f0f0f0 \n"
  ".word 0xbabababa \n"

  "arm_ldr_pc_pre_index_imm_negative_func: \n"
  "ldr r1, [r1, #12] \n"
  "add r0, r0, r1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_ldr_pc_pre_index_imm_negative)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_ldr_pc_pre_index_imm_negative), CODE_SIZE (arm_ldr_pc_pre_index_imm_negative), 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm_negative,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "adr r1, arm_ldr_pc_post_index_imm_negative_data \n"
  "ldr pc, [r1], #-8 \n"
  "udf #16 \n"


  ".word 0xbabababa \n"
  ".word 0xf0f0f0f0 \n"
  "arm_ldr_pc_post_index_imm_negative_data: \n"
  ".word arm_ldr_pc_post_index_imm_negative_func \n"

  "arm_ldr_pc_post_index_imm_negative_func: \n"
  "ldr r1, [r1, #0] \n"
  "add r0, r0, r1 \n"
  "mov pc, lr \n"
);

TESTCASE (arm_ldr_pc_post_index_imm_negative)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_ldr_pc_post_index_imm_negative), CODE_SIZE (arm_ldr_pc_post_index_imm_negative), 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 16);
}

TESTCODE (arm_sub_pc,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "b 2f \n"

  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "sub pc, pc, #20 \n"
);

TESTCASE (arm_sub_pc)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_sub_pc), CODE_SIZE (arm_sub_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 24);
}

TESTCODE (arm_add_pc,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add pc, pc, #4 \n"

  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "b 1b \n \n"
);

TESTCASE (arm_add_pc)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (arm_add_pc), CODE_SIZE (arm_add_pc), 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 24);
}


TESTCODE (call_thumb,
  ".arm \n"
  "push {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "blx 3f \n"
  "bl 1f \n"
  "pop {pc} \n"

  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  ".thumb_func \n"
  "3: \n"
  "push {lr} \n"
  "add r0, r0, #1 \n"
  "blx 2b \n"
  "pop {pc} \n"
  ".arm \n"
);

TESTCASE (call_thumb)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_CALL,
      CODE_START (call_thumb), CODE_SIZE (call_thumb), 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR(call, 1, location, func + 12);
  GUM_ASSERT_EVENT_ADDR(call, 1, target, func + 41);
  GUM_ASSERT_EVENT_ADDR(call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR(call, 2, location, func + 44);
  GUM_ASSERT_EVENT_ADDR(call, 2, target, func + 32);
  GUM_ASSERT_EVENT_ADDR(call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR(call, 3, location, func + 16);
  GUM_ASSERT_EVENT_ADDR(call, 3, target, func + 24);
  GUM_ASSERT_EVENT_ADDR(call, 3, depth, 1);
}

TESTCODE (branch_thumb,
  ".arm \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"

  "adr r1, f1 \n"
  "adr r2, f2 \n"
  "add r2, r2, #1 \n"

  "bx r2 \n"
  "f1: \n"
  "b 2f \n"
  "1: \n"

  "mov pc, lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "b 1b \n"

  ".thumb_func \n"
  "f2: \n"
  "add r0, r0, #1 \n"
  "bx r1 \n"

  ".arm \n"
);

TESTCASE (branch_thumb)
{
  GumAddress func;

  func = invoke_arm_expecting_return_value (fixture, GUM_BLOCK,
      CODE_START (branch_thumb), CODE_SIZE (branch_thumb), 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR(block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR(block, 0, end, func + 24);

  GUM_ASSERT_EVENT_ADDR(block, 1, begin, func + 40);
  GUM_ASSERT_EVENT_ADDR(block, 1, end, func + 44);

  GUM_ASSERT_EVENT_ADDR(block, 2, begin, func + 24);
  GUM_ASSERT_EVENT_ADDR(block, 2, end, func + 28);

  GUM_ASSERT_EVENT_ADDR(block, 3, begin, func + 32);
  GUM_ASSERT_EVENT_ADDR(block, 3, end, func + 40);
}

GUM_NOINLINE static void
pretend_workload (GumMemoryRange * runner_range)
{
  lzma_stream stream = LZMA_STREAM_INIT;
  const uint32_t preset = 9 | LZMA_PRESET_EXTREME;
  lzma_ret ret;
  guint8 * outbuf;
  gsize outbuf_size;
  const gsize outbuf_size_increment = 1024 * 1024;

  ret = lzma_easy_encoder (&stream, preset, LZMA_CHECK_CRC64);
  g_assert_cmpint (ret, ==, LZMA_OK);

  outbuf_size = outbuf_size_increment;
  outbuf = malloc (outbuf_size);

  stream.next_in = GSIZE_TO_POINTER (runner_range->base_address);
  stream.avail_in = MIN (runner_range->size, 65536);
  stream.next_out = outbuf;
  stream.avail_out = outbuf_size;

  while (TRUE)
  {
    ret = lzma_code (&stream, LZMA_FINISH);

    if (stream.avail_out == 0)
    {
      gsize compressed_size;

      compressed_size = outbuf_size;

      outbuf_size += outbuf_size_increment;
      outbuf = realloc (outbuf, outbuf_size);

      stream.next_out = outbuf + compressed_size;
      stream.avail_out = outbuf_size - compressed_size;
    }

    if (ret != LZMA_OK)
    {
      g_assert_cmpint (ret, ==, LZMA_STREAM_END);
      break;
    }
  }

  lzma_end (&stream);

  free (outbuf);
}

extern void test_arm_stalker_call_workload (GumMemoryRange * runner_range);

TESTCODE (call_workload,
  ".arm \n"
  "test_arm_stalker_call_workload: \n"

  "push {lr} \n"
  "bl pretend_workload \n"
  "pop {pc} \n"
);

static gboolean
test_log_fatal_func (const gchar *log_domain,
                      GLogLevelFlags log_level,
                      const gchar *message,
                      gpointer user_data)
{
  return FALSE;
}

static GLogWriterOutput
test_log_writer_func (GLogLevelFlags log_level,
                      const GLogField *fields,
                      gsize n_fields,
                      gpointer user_data)
{
  return G_LOG_WRITER_HANDLED;
}

TESTCASE (can_follow_workload)
{
  GumMemoryRange runner_range;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_true (runner_range.base_address != 0 && runner_range.size >= 16);

  runner_range.size = 16;

  test_arm_stalker_call_workload (&runner_range);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = ( GUM_RET );

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  test_arm_stalker_call_workload (&runner_range);

  gum_stalker_unfollow_me (fixture->stalker);

  GUM_ASSERT_EVENT_ADDR(ret, fixture->sink->events->len - 1, location,
      CODE_START (call_workload) + 8);
}

TESTCASE (performance)
{

  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble normal_cold, normal_hot;
  gdouble stalker_cold, stalker_hot;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_hot = g_timer_elapsed (timer, NULL);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = GUM_NOTHING;

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                        "add with shift not supported");

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_hot = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);
  g_print ("\n");
  g_print ("<normal_cold=%f>\n", normal_cold);
  g_print ("<normal_hot=%f>\n", normal_hot);
  g_print ("<stalker_cold=%f>\n", stalker_cold);
  g_print ("<stalker_hot=%f>\n", stalker_hot);
  g_print ("<ratio_cold=%f>\n", stalker_cold / normal_hot);
  g_print ("<ratio_hot=%f>\n", stalker_hot / normal_hot);
}

TESTCASE (custom_transformer)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      duplicate_adds, NULL, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 4);
}

static void
duplicate_adds (GumStalkerIterator * iterator,
                GumStalkerWriter * output,
                gpointer user_data)
{
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->id == ARM_INS_ADD)
    {
      gum_arm_writer_put_bytes (&output->arm, insn->bytes, insn->size);
    }
  }
}

TESTCASE (unfollow_should_be_allowed_before_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_after_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_before_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_after_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  stalk_arm_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

static void
unfollow_during_transform (GumStalkerIterator * iterator,
                           GumStalkerWriter * output,
                           gpointer user_data)
{
  UnfollowTransformContext * ctx = user_data;
  const cs_insn * insn;

  if (ctx->num_blocks_transformed == ctx->target_block)
  {
    gint n;

    for (n = 0; n != ctx->max_instructions &&
        gum_stalker_iterator_next (iterator, &insn); n++)
    {
      gum_stalker_iterator_keep (iterator);
    }

    gum_stalker_unfollow_me (ctx->stalker);
  }
  else
  {
    while (gum_stalker_iterator_next (iterator, &insn))
      gum_stalker_iterator_keep (iterator);
  }

  ctx->num_blocks_transformed++;
}

TESTCASE (follow_syscall)
{
  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (follow_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;
#ifdef HAVE_LINUX
  int prev_dumpable;

  /* Android spawns non-debuggable applications as not dumpable by default. */
  prev_dumpable = prctl (PR_GET_DUMPABLE);
  prctl (PR_SET_DUMPABLE, 0);
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target", run_stalked_briefly, &channel);
  thread_id = sdc_await_thread_id (&channel);

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);
  gum_stalker_follow (fixture->stalker, thread_id, NULL,
      GUM_EVENT_SINK (fixture->sink));
  sdc_put_follow_confirmation (&channel);

  sdc_await_run_confirmation (&channel);
  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  gum_stalker_unfollow (fixture->stalker, thread_id);
  sdc_put_unfollow_confirmation (&channel);

  sdc_await_flush_confirmation (&channel);
  gum_fake_event_sink_reset (fixture->sink);

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  sdc_finalize (&channel);

#ifdef HAVE_LINUX
  prctl (PR_SET_DUMPABLE, prev_dumpable);
#endif
}

static gpointer
run_stalked_briefly (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  sdc_put_run_confirmation (channel);

  sdc_await_unfollow_confirmation (channel);

  sdc_put_flush_confirmation (channel);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (unfollow_should_handle_terminated_thread)
{
  guint i;

  for (i = 0; i != 10; i++)
  {
    StalkerDummyChannel channel;
    GThread * thread;
    GumThreadId thread_id;

    sdc_init (&channel);

    thread = g_thread_new ("stalker-test-target", run_stalked_into_termination,
        &channel);
    thread_id = sdc_await_thread_id (&channel);

    fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);
    gum_stalker_follow (fixture->stalker, thread_id, NULL,
        GUM_EVENT_SINK (fixture->sink));
    sdc_put_follow_confirmation (&channel);

    g_thread_join (thread);

    if (i % 2 == 0)
      g_usleep (50000);

    gum_stalker_unfollow (fixture->stalker, thread_id);

    sdc_finalize (&channel);

    while (gum_stalker_garbage_collect (fixture->stalker))
      g_usleep (10000);
  }
}

static gpointer
run_stalked_into_termination (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  return NULL;
}

TESTCASE (pthread_create)
{
  int ret;
  pthread_t thread;
  int number = 0;

  fixture->sink->mask = (GumEventType) GUM_NOTHING;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  ret = pthread_create (&thread, NULL, increment_integer, (gpointer) &number);
  g_assert_cmpint (ret, ==, 0);

  ret = pthread_join (thread, NULL);
  g_assert_cmpint (ret, ==, 0);

  g_assert_cmpint (number, ==, 1);

  gum_stalker_unfollow_me (fixture->stalker);
}

static gpointer
increment_integer (gpointer data)
{
  int * number = (int *) data;
  *number += 1;
  return NULL;
}

TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = (GumEventType) (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}
