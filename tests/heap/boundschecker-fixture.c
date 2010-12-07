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

#include "gumboundschecker.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define BOUNDSCHECKER_TESTCASE(NAME) \
    void test_bounds_checker_ ## NAME ( \
        TestBoundsCheckerFixture * fixture, gconstpointer data)
#define BOUNDSCHECKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/BoundsChecker", \
        test_bounds_checker, NAME, TestBoundsCheckerFixture)

typedef struct _TestBoundsCheckerFixture
{
  GumBoundsChecker * checker;
} TestBoundsCheckerFixture;

static void
test_bounds_checker_fixture_setup (TestBoundsCheckerFixture * fixture,
                                   gconstpointer data)
{
  fixture->checker = gum_bounds_checker_new ();
}

static void
test_bounds_checker_fixture_teardown (TestBoundsCheckerFixture * fixture,
                                      gconstpointer data)
{
  g_object_unref (fixture->checker);
}

#define ATTACH_CHECKER() \
    gum_bounds_checker_attach_to_apis (fixture->checker, \
        test_util_heap_apis ())
#define DETACH_CHECKER() \
    gum_bounds_checker_detach (fixture->checker)