/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpagepool.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define PAGEPOOL_TESTCASE(NAME) \
    void test_page_pool_ ## NAME ( \
        TestPagePoolFixture * fixture, gconstpointer data)
#define PAGEPOOL_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/PagePool", test_page_pool, NAME, \
        TestPagePoolFixture)

typedef struct _TestPagePoolFixture
{
  GumPagePool * pool;
} TestPagePoolFixture;

static void
test_page_pool_fixture_setup (TestPagePoolFixture * fixture,
                              gconstpointer data)
{
}

static void
test_page_pool_fixture_teardown (TestPagePoolFixture * fixture,
                                 gconstpointer data)
{
  g_object_unref (fixture->pool);
}

#define SETUP_POOL(ptr, protect_mode, n_pages) \
    fixture->pool = gum_page_pool_new (protect_mode, n_pages); \
    *ptr = fixture->pool
