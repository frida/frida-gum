/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

TESTLIST_BEGIN (stalker)
  TESTENTRY (no_events)
  TESTENTRY (trust_is_zero)
  TESTENTRY (trust_unsupported)
TESTLIST_END ()

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

static const guint32 flat_code[] = {
  0xe0400000, /* SUB R0, R0, R0 */
  0xe2800001, /* ADD R0, R0, #1 */
  0xe2800001, /* ADD R0, R0, #1 */
  0xe1a0f00e  /* MOV PC, LR     */
};

static StalkerTestFunc
invoke_flat_expecting_return_value (TestArmStalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm_stalker_fixture_dup_code (fixture,
      flat_code, sizeof (flat_code));

  fixture->sink->mask = mask;
  ret = test_arm_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat (TestArmStalkerFixture * fixture,
             GumEventType mask)
{
  return invoke_flat_expecting_return_value (fixture, mask, 2);
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