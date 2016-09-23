/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumbacktracer.h"

#include "testutil.h"
#include "valgrind.h"

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
  fixture->backtracer = gum_backtracer_make_accurate ();
}

static void
test_backtracer_fixture_teardown (TestBacktracerFixture * fixture,
                                  gconstpointer data)
{
  if (fixture->backtracer != NULL)
    g_object_unref (fixture->backtracer);
}
