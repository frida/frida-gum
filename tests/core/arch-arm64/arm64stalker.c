/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64stalker-fixture.c"

TEST_LIST_BEGIN (arm64stalker)
  STALKER_ARM64_TESTENTRY (heap_api)
TEST_LIST_END ()

static void pretend_workload (void);
static gpointer stalker_victim (gpointer data);
static void invoke_follow_return_code (TestArm64StalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestArm64StalkerFixture * fixture);

gint gum_stalker_dummy_global_to_trick_optimizer = 0;

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
