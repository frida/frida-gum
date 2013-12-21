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

#include "guminstancetracker.h"

#ifdef G_OS_WIN32

#include "dummyclasses.h"
#include "testutil.h"

#define INSTRACKER_TESTCASE(NAME) \
    void test_instance_tracker_ ## NAME ( \
        TestInstanceTrackerFixture * fixture, gconstpointer data)
#define INSTRACKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/InstanceTracker", test_instance_tracker, \
        NAME, TestInstanceTrackerFixture)

typedef struct _TestInstanceTrackerFixture
{
  GumInstanceTracker * tracker;
} TestInstanceTrackerFixture;

static void
test_instance_tracker_fixture_setup (TestInstanceTrackerFixture * fixture,
                                    gconstpointer data)
{
  fixture->tracker = gum_instance_tracker_new ();
  gum_instance_tracker_begin (fixture->tracker, NULL);
}

static void
test_instance_tracker_fixture_teardown (TestInstanceTrackerFixture * fixture,
                                       gconstpointer data)
{
  gum_instance_tracker_end (fixture->tracker);
  g_object_unref (fixture->tracker);
}

#endif /* G_OS_WIN32 */
