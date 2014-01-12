/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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
