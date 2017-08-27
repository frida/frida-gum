/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm64-fixture.c"

#import <UIKit/UIKit.h>

TEST_LIST_BEGIN (stalker_darwin)
  STALKER_TESTENTRY (foundation)
TEST_LIST_END ()

STALKER_TESTCASE (foundation)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  fixture->sink->mask = (GumEventType) GUM_CALL;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  @autoreleasepool
  {
    [NSDictionary dictionary];
  }

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}
