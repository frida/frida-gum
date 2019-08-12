/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminstancetracker.h"

#ifdef G_OS_WIN32

#include "dummyclasses.h"
#include "testutil.h"

#define TESTCASE(NAME) \
    void test_instance_tracker_ ## NAME ( \
        TestInstanceTrackerFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Heap/InstanceTracker", test_instance_tracker, \
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
