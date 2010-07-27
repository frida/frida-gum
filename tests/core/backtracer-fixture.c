/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumbacktracer.h"

#include "testutil.h"

#include <stdlib.h>

#define BACKTRACER_TESTCASE(NAME) \
    void test_backtracer_ ## NAME ( \
        TestBacktracerFixture * fixture, gconstpointer data)
#define BACKTRACER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Backtracer", test_backtracer, NAME, \
        TestBacktracerFixture)

typedef struct _TestBacktracerFixture
{
  GumBacktracer * backtracer;
} TestBacktracerFixture;

static void
test_backtracer_fixture_setup (TestBacktracerFixture * fixture,
                               gconstpointer data)
{
  fixture->backtracer = gum_backtracer_make_default ();
}

static void
test_backtracer_fixture_teardown (TestBacktracerFixture * fixture,
                                  gconstpointer data)
{
  g_object_unref (fixture->backtracer);
}
