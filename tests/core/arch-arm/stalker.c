/*
 * Copyright (C) 2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2012 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "stalker-fixture.c"

TEST_LIST_BEGIN (stalker)
  STALKER_TESTENTRY (call)
TEST_LIST_END ()

static const guint8 flat_code[] = {
    0x33, 0xc0, /* xor eax, eax */
    0xff, 0xc0, /* inc eax      */
    0xff, 0xc0, /* inc eax      */
    0xc3        /* retn         */
};

static StalkerTestFunc
invoke_flat (TestStalkerFixture * fixture,
             GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 2);

  return func;
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
  g_assert_cmphex (GPOINTER_TO_SIZE (ev->location),
      ==, GPOINTER_TO_SIZE (fixture->last_invoke_calladdr));
  g_assert_cmphex (GPOINTER_TO_SIZE (ev->target), ==, GPOINTER_TO_SIZE (func));
}

