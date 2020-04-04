/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

#include <lzma.h>

TESTLIST_BEGIN (stalker)
  TESTENTRY (flat_code)
  TESTENTRY (no_events)
  TESTENTRY (trust_is_zero)
  TESTENTRY (trust_unsupported)
  TESTENTRY (deactivate_unsupported)
  TESTENTRY (activate_unsupported)
  TESTENTRY (add_call_probe_unsupported)
  TESTENTRY (remove_call_probe_unsupported)
  TESTENTRY (follow_unsupported)
  TESTENTRY (unfollow_unsupported)
  TESTENTRY (compile_events_unsupported)
  TESTENTRY (exec_events_generated)
  TESTENTRY (call_events_generated)
  TESTENTRY (block_events_generated)
  TESTENTRY (nested_call_events_generated)
  TESTENTRY (nested_ret_events_generated)
  TESTENTRY (unmodified_lr)
  TESTENTRY (excluded_range)
  TESTENTRY (excluded_range_call_events)
  TESTENTRY (excluded_range_ret_events)
  TESTENTRY (pop_pc_ret_events_generated)
  TESTENTRY (pop_just_pc_ret_events_generated)
  TESTENTRY (ldm_pc_ret_events_generated)
  TESTENTRY (branch_cc_block_events_generated)
  TESTENTRY (branch_link_cc_block_events_generated)
  TESTENTRY (cc_excluded_range)
  TESTENTRY (excluded_thumb)
  TESTENTRY (excluded_thumb_branch)
  TESTENTRY (ldr_pc)
  TESTENTRY (performance)
  TESTENTRY (can_follow_workload)
TESTLIST_END ()

gint gum_stalker_dummy_global_to_trick_optimizer = 0;


extern const void flat_code;
extern const void flat_code_end;

asm (
  "flat_code: \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
  "flat_code_end: \n"
);

#define FLAT_CODE_INSN_COUNT ((&flat_code_end - &flat_code)/sizeof(guint32))

static StalkerTestFunc
invoke_expecting_return_value (TestArmStalkerFixture * fixture,
                               GumEventType mask,
                               const guint32* code,
                               guint32 len,
                               guint32 expected_return_value)
{
  StalkerTestFunc func;
  guint32 ret;

  func = (StalkerTestFunc) test_arm_stalker_fixture_dup_code (fixture,
      code, len);

  fixture->sink->mask = mask;
  ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpuint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat_expecting_return_value (TestArmStalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  return invoke_expecting_return_value(fixture, mask, &flat_code,
                                       &flat_code_end - &flat_code,
                                       expected_return_value);
}

TESTCASE (flat_code)
{
  g_assert_cmpuint ((&flat_code_end - &flat_code), ==, 16);
  guint* code = (guint*)&flat_code;
  g_assert_cmpuint(code[0], ==, 0xe0400000);
  g_assert_cmpuint(code[1], ==, 0xe2800001);
  g_assert_cmpuint(code[2], ==, 0xe2800001);
  g_assert_cmpuint(code[3], ==, 0xe1a0f00e);
}

TESTCASE (no_events)
{
  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (trust_is_zero)
{
  gint threshold = gum_stalker_get_trust_threshold(fixture->stalker);
  g_assert_cmpuint (threshold, ==, 0);
}

TESTCASE (trust_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Trust threshold unsupported");
  gum_stalker_set_trust_threshold(fixture->stalker, 10);
  g_test_assert_expected_messages();
}

TESTCASE (deactivate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Activate/deactivate unsupported");
  gum_stalker_deactivate(fixture->stalker);
  g_test_assert_expected_messages();
}

TESTCASE (activate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Activate/deactivate unsupported");
  gum_stalker_activate(fixture->stalker, NULL);
  g_test_assert_expected_messages();
}

static void dummyCallProbe (GumCallSite * site, gpointer user_data)
{

}

static void dummyDestroyNotify (gpointer       data)
{

}

TESTCASE (add_call_probe_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Call probes unsupported");
  GumProbeId id = gum_stalker_add_call_probe(fixture->stalker, NULL,
                                             dummyCallProbe,
                                             NULL, dummyDestroyNotify);
  g_test_assert_expected_messages();
  g_assert_cmpuint (id, ==, 0);
}

TESTCASE (remove_call_probe_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Call probes unsupported");
  gum_stalker_remove_call_probe(fixture->stalker, 10);
  g_test_assert_expected_messages();
}

TESTCASE (follow_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Follow unsupported");
  gum_stalker_follow(fixture->stalker, 0, fixture->transformer,
                     (GumEventSink*)fixture->sink);
  g_test_assert_expected_messages();
}

TESTCASE (unfollow_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Unfollow unsupported");
  gum_stalker_unfollow(fixture->stalker, 0);
  g_test_assert_expected_messages();
}

TESTCASE (compile_events_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "Compile events unsupported");

  invoke_flat_expecting_return_value(fixture, GUM_COMPILE, 2);
  g_test_assert_expected_messages();
}

// gef➤  x/20i $pc
//    0x626008:	ldr	r2, [pc, #40]	; 0x626038
//    0x62600c:	ldr	r1, [pc, #40]	; 0x62603c
//    0x626010:	ldr	r0, [pc, #40]	; 0x626040
//    0x626014:	bl	0x65f6c <gum_stalker_follow_me>
//    0x626018:	ldr	r0, [pc, #36]	; 0x626044
//    0x62601c:	bl	0x624000
//    0x626020:	ldr	r1, [pc, #32]	; 0x626048
//    0x626024:	str	r0, [r1]
//    0x626028:	ldr	r0, [pc, #16]	; 0x626040
//    0x62602c:	bl	0x65504 <gum_stalker_unfollow_me>
//    0x626030:	ldmfd	sp!, {lr}
//    0x626034:	mov	pc, lr


TESTCASE (exec_events_generated)
{
  GumExecEvent * ev;

  StalkerTestFunc func = invoke_flat_expecting_return_value (fixture, GUM_EXEC, 2);
  g_assert_cmpuint (fixture->sink->events->len, ==,
                    INVOKER_INSN_COUNT + FLAT_CODE_INSN_COUNT);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_EXEC);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->invoker + INVOKER_IMPL_OFFSET);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==,
    fixture->invoker + INVOKER_IMPL_OFFSET + 4);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 3).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 4);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 4).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 8);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 5).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 12);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 6).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==,
    fixture->invoker + INVOKER_IMPL_OFFSET + 8);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 7).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==,
    fixture->invoker + INVOKER_IMPL_OFFSET + 12);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 8).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==,
    fixture->invoker + INVOKER_IMPL_OFFSET + 16);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 9).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==,
    fixture->invoker + INVOKER_IMPL_OFFSET + 20);

}

TESTCASE (call_events_generated)
{
  GumCallEvent * ev;

  StalkerTestFunc func = invoke_flat_expecting_return_value (fixture, GUM_CALL,
                                                             2);
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 0);
}

extern const void branch_code;
extern const void branch_code_end;

asm (
  "branch_code: \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "b 1f \n"
  "udf #0 \n"
  "1: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"
  "branch_code_end: \n"
);

TESTCASE (block_events_generated)
{
  GumBlockEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_BLOCK,
                                     &branch_code,
                                     &branch_code_end - &branch_code,
                                     2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_BLOCK);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + (3 * 4));
}

extern const void nested_call_code;
extern const void nested_call_code_end;

asm (
  "nested_call_code: \n"
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

  "nested_call_code_end: \n"
);

TESTCASE (nested_call_events_generated)
{
  GumCallEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_CALL,
                                     &nested_call_code,
                                     &nested_call_code_end - &nested_call_code,
                                     4);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 3);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 0);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (3 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (7 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (9 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (12 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 3).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (4 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (12 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

TESTCASE (nested_ret_events_generated)
{
  GumRetEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_RET,
                                     &nested_call_code,
                                     &nested_call_code_end - &nested_call_code,
                                     4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (13 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (10 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 3);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (11 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (4 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (13 * 4));
  GUM_ASSERT_CMPADDR (ev->target, ==, func + (5 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 3).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + (6 * 4));
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

extern const void unmodified_lr_code;
extern const void unmodified_lr_code_end;

asm (
  "unmodified_lr_code: \n"
  "stmdb sp!, {lr} \n"
  "bl 1f \n"
  ".word 0xecececec \n"
  "1: \n"
  "ldr r0, [lr] \n"
  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"
  "unmodified_lr_code_end: \n"
);

TESTCASE (unmodified_lr)
{
  invoke_expecting_return_value (fixture, 0,
                                 &unmodified_lr_code,
                                 &unmodified_lr_code_end - &unmodified_lr_code,
                                 0xecececec);
}

extern const void excluded_range_code;
extern const void excluded_range_code_end;

asm (
  "excluded_range_code: \n"
  "stmdb sp!, {lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {lr} \n"
  "mov pc,lr \n"

  "2: \n"
  "add r0, r0, #1 \n"
  "mov pc, lr \n"

  "excluded_range_code_end: \n"
);

TESTCASE (excluded_range)
{
  GumExecEvent * ev;

  StalkerTestFunc func = (StalkerTestFunc)
    test_arm_stalker_fixture_dup_code (fixture, &excluded_range_code,
      &excluded_range_code_end - &excluded_range_code);

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 24,
    .size = 8
  };

  gum_stalker_exclude (fixture->stalker, &r);


  fixture->sink->mask = GUM_EXEC;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpuint (ret, ==, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_EXEC);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 3).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 4);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 4).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 8);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 5).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 12);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 6).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 7).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 20);
}

extern const void excluded_range_call_event_code;
extern const void excluded_range_call_event_code_end;

asm (
  "excluded_range_call_event_code: \n"
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

  "excluded_range_call_event_code_end: \n"
);

TESTCASE (excluded_range_call_events)
{
  GumCallEvent * ev;

  StalkerTestFunc func = (StalkerTestFunc)
    test_arm_stalker_fixture_dup_code (fixture, &excluded_range_call_event_code,
      &excluded_range_call_event_code_end - &excluded_range_call_event_code);

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 40,
    .size = 16
  };

  gum_stalker_exclude (fixture->stalker, &r);


  fixture->sink->mask = GUM_CALL;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 12);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 40);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 24);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

TESTCASE (excluded_range_ret_events)
{
  GumRetEvent * ev;

  StalkerTestFunc func = (StalkerTestFunc)
    test_arm_stalker_fixture_dup_code (fixture, &excluded_range_call_event_code,
      &excluded_range_call_event_code_end - &excluded_range_call_event_code);

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 40,
    .size = 16
  };

  gum_stalker_exclude (fixture->stalker, &r);


  fixture->sink->mask = GUM_RET;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpuint (ret, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 28);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 20);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 20);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}


extern const void pop_pc_code;
extern const void pop_pc_code_end;

asm (
  "pop_pc_code: \n"
  "stmdb sp!, {r4-r8, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {r4-r8, pc} \n"

  "2: \n"
  "stmdb sp!, {r1-r3, lr} \n"
  "add r0, r0, #1 \n"
  "ldmia sp!, {r1-r3, pc} \n"

  "pop_pc_code_end: \n"
);

TESTCASE (pop_pc_ret_events_generated)
{
  GumRetEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_RET,
                                     &pop_pc_code,
                                     &pop_pc_code_end - &pop_pc_code,
                                     2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 28);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

extern const void pop_just_pc_code;
extern const void pop_just_pc_code_end;

asm (
  "pop_just_pc_code: \n"
  "stmdb sp!, {r4-r8, lr} \n"
  "sub r0, r0, r0 \n"
  "add r0, r0, #1 \n"
  "bl 2f \n"
  "ldmia sp!, {r4-r8, pc} \n"

  "2: \n"
  "stmdb sp!, {lr} \n"
  "add r0, r0, #1 \n"
  "ldmia sp!, {pc} \n"

  "pop_just_pc_code_end: \n"
);

TESTCASE (pop_just_pc_ret_events_generated)
{
  GumRetEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_RET,
                                     &pop_just_pc_code,
                                     &pop_just_pc_code_end - &pop_just_pc_code,
                                     2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 28);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}


extern const void ldm_pc_code;
extern const void ldm_pc_code_end;

asm (
  "ldm_pc_code: \n"
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

  "ldm_pc_code_end: \n"
);

TESTCASE (ldm_pc_ret_events_generated)
{
  GumRetEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_RET,
                                     &ldm_pc_code,
                                     &ldm_pc_code_end - &ldm_pc_code,
                                     2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 32);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 2);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

extern const void b_cc_code;
extern const void b_cc_code_end;

asm (
  "b_cc_code: \n"
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
  "b_cc_code_end: \n"
);

TESTCASE (branch_cc_block_events_generated)
{
  GumBlockEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_BLOCK,
                                     &b_cc_code,
                                     &b_cc_code_end - &b_cc_code,
                                     10);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_BLOCK);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + 16);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func + 20);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + 28);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 2).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func + 28);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + 40);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 3).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func + 44);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + 52);
}

extern const void bl_cc_code;
extern const void bl_cc_code_end;

asm (
  "bl_cc_code: \n"
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
  "bl_cc_code_end: \n"
);

TESTCASE (branch_link_cc_block_events_generated)
{
  GumCallEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_CALL,
                                     &bl_cc_code,
                                     &bl_cc_code_end - &bl_cc_code,
                                     5);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 2);

  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 48);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 2).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 32);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 64);

}

extern const void cc_excluded_range_code;
extern const void cc_excluded_range_code_end;

asm (
  "cc_excluded_range_code: \n"
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

  "cc_excluded_range_code_end: \n"
);

TESTCASE (cc_excluded_range)
{
  GumCallEvent * ev;

  StalkerTestFunc func = (StalkerTestFunc)
    test_arm_stalker_fixture_dup_code (fixture, &cc_excluded_range_code,
      &cc_excluded_range_code_end - &cc_excluded_range_code);

  GumMemoryRange r = {
    .base_address = GUM_ADDRESS(func) + 36,
    .size = 36
  };

  gum_stalker_exclude (fixture->stalker, &r);


  fixture->sink->mask = GUM_CALL;
  guint32 ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpuint (ret, ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);

  ev =
      &g_array_index (fixture->sink->events, GumEvent, 1).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 36);
}


extern const void excluded_thumb_code;
extern const void excluded_thumb_code_end;

asm (
  "excluded_thumb_code: \n"
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
  "excluded_thumb_code_end: \n"
);

TESTCASE (excluded_thumb)
{
  GumCallEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_CALL,
                                     &excluded_thumb_code,
                                     &excluded_thumb_code_end - &excluded_thumb_code,
                                     4);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT + 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 1).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 12);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 41);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 2).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, func + 16);
  GUM_ASSERT_CMPADDR (ev->target, ==, func + 24);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 1);
}

extern const void excluded_thumb_branch_code;
extern const void excluded_thumb_branch_code_end;

asm (
  "excluded_thumb_branch_code: \n"
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

  ""
  "excluded_thumb_branch_code_end: \n"
);

TESTCASE (excluded_thumb_branch)
{
  GumCallEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_CALL,
                                     &excluded_thumb_branch_code,
                                     &excluded_thumb_branch_code_end - &excluded_thumb_branch_code,
                                     3);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 0);
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


extern const void ldr_pc_code;
extern const void ldr_pc_code_end;

asm (
  "ldr_pc_code: \n"
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

  "ldr_pc_code_end: \n"
);

TESTCASE (ldr_pc)
{
  GumBlockEvent * ev;

  StalkerTestFunc func =
      invoke_expecting_return_value (fixture, GUM_BLOCK,
                                     &ldr_pc_code,
                                     &ldr_pc_code_end - &ldr_pc_code,
                                     2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_BLOCK);

  ev =
    &g_array_index (fixture->sink->events, GumEvent, 0).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + 12);
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

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble normal_cold, normal_hot;
  gdouble stalker_cold, stalker_hot;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_true (runner_range.base_address != 0 && runner_range.size != 0);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_hot = g_timer_elapsed (timer, NULL);

  fixture->sink->mask = GUM_NOTHING;

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

  g_print ("<normal_cold=%f>\n", normal_cold);
  g_print ("<normal_hot=%f>\n", normal_hot);
  g_print ("<stalker_cold=%f>\n", stalker_cold);
  g_print ("<stalker_hot=%f>\n", stalker_hot);
  g_print ("<ratio_cold=%f>\n", stalker_cold / normal_hot);
  g_print ("<ratio_hot=%f>\n", stalker_hot / normal_hot);
}

extern const void call_workload_code;
extern void call_workload(GumMemoryRange * runner_range);

asm (
  "call_workload_code: \n"
  "call_workload: \n"

  "push {lr} \n"
  "bl pretend_workload \n"
  "pop {pc} \n"
);

TESTCASE (can_follow_workload)
{
  GumMemoryRange runner_range;
  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_true (runner_range.base_address != 0 && runner_range.size != 0);

  fixture->sink->mask = (GUM_EXEC | GUM_CALL | GUM_RET);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  call_workload(&runner_range);

  gum_stalker_unfollow_me (fixture->stalker);
  show_events(fixture->sink);
  g_print("call_workload_code: %p\n", &call_workload_code);
  g_print("MASK: 0x%08x\n", fixture->sink->mask);
  g_print("EVENTS: %d\n", fixture->sink->events->len);
}

// Tidy the jump generated code to not use hard-coded instructions
// Add code to check we run to the end of the performance test.

// Other forms of branch instructions
  // LDR PC - Used in PLT as a trampoline (branch).
  // LDRLS - switches
  // MOV PC - call but with LR moved immediately before
  // TBB/TBH - switches


// Add code to show call stack with blocks (GUM_CALL, GUM_BLOCK, GUM_RET)

// Detect calls by tracking modifications to LR?
// Compare test list to aarch64
// Test we can unfollow (move check to virtualize funcs)
// Style rules
