/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

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
                               guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm_stalker_fixture_dup_code (fixture,
      code, len);

  fixture->sink->mask = mask;
  ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

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

static StalkerTestFunc
invoke_flat (TestArmStalkerFixture * fixture,
             GumEventType mask)
{
  return invoke_flat_expecting_return_value (fixture, mask, 2);
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
  invoke_flat (fixture, GUM_NOTHING);
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

  invoke_flat(fixture, GUM_COMPILE);
  g_test_assert_expected_messages();
}

TESTCASE (exec_events_generated)
{
  GumExecEvent * ev;

  invoke_flat (fixture, GUM_EXEC);
  //TODO: Update this when we can follow the call
  g_assert_cmpuint (fixture->sink->events->len, ==,
                    INVOKER_INSN_COUNT + FLAT_CODE_INSN_COUNT);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_EXEC);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).exec;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->invoker + INVOKER_IMPL_OFFSET);
}

TESTCASE (call_events_generated)
{
  GumCallEvent * ev;

  StalkerTestFunc func = invoke_flat (fixture, GUM_CALL);
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
  GUM_ASSERT_CMPADDR (ev->depth, ==, 0);
}

TESTCASE (block_events_generated)
{
  GumBlockEvent * ev;


  const guint32 branch_code[] = {
    0xe0400000, /* SUB R0, R0, R0 */
    0xe2800001, /* ADD R0, R0, #1 */
    0xea000000, /* B #8 */
    0xe7f000f0, /* UDF #0 */
    0xe2800001, /* ADD R0, R0, #1 */
    0xe1a0f00e  /* MOV PC, LR     */
  };

  StalkerTestFunc func = invoke_expecting_return_value (fixture, GUM_BLOCK,
                                                        branch_code,
                                                        sizeof(branch_code),
                                                        2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_BLOCK);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, 0).block;
  GUM_ASSERT_CMPADDR (ev->begin, ==, func);
  GUM_ASSERT_CMPADDR (ev->end, ==, func + (3 * 4));
}

// Move assembly code into __asm__ blocks

// Compare test list to aarch64
// Test we can emit events for ret
// Test calling mulitple levels deep and check call depth
// Check thumb/jazelle is excluded.
// Test adding excluded ranges
// Test we can unfollow (move check to virtualize funcs)
// Test conditional calls and jmps