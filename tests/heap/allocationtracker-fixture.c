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

#include "gumallocationtracker.h"

#include "dummyclasses.h"
#include "fakebacktracer.h"
#include "gumhash.h"
#include "testutil.h"

#define ALLOCTRACKER_TESTCASE(NAME) \
    void test_allocation_tracker_ ## NAME ( \
        TestAllocationTrackerFixture * fixture, gconstpointer data)
#define ALLOCTRACKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/AllocationTracker", \
        test_allocation_tracker, NAME, TestAllocationTrackerFixture)

typedef struct _TestAllocationTrackerFixture
{
  GumAllocationTracker * tracker;
} TestAllocationTrackerFixture;

static void
test_allocation_tracker_fixture_setup (
    TestAllocationTrackerFixture * fixture,
    gconstpointer data)
{
  fixture->tracker = gum_allocation_tracker_new ();
}

static void
test_allocation_tracker_fixture_teardown (
    TestAllocationTrackerFixture * fixture,
    gconstpointer data)
{
  g_object_unref (fixture->tracker);
}

#define DUMMY_BLOCK_A (GUINT_TO_POINTER (0xDEADBEEF))
#define DUMMY_BLOCK_B (GUINT_TO_POINTER (0xB00BFACE))
#define DUMMY_BLOCK_C (GUINT_TO_POINTER (0xBEEFFACE))
#define DUMMY_BLOCK_D (GUINT_TO_POINTER (0xBEEFB00B))
#define DUMMY_BLOCK_E (GUINT_TO_POINTER (0xBEB00BEF))

static const GumReturnAddress dummy_return_addresses_a[] =
{
  GUINT_TO_POINTER (0x1234),
  GUINT_TO_POINTER (0x4321)
};

static const GumReturnAddress dummy_return_addresses_b[] =
{
  GUINT_TO_POINTER (0x1250),
  GUINT_TO_POINTER (0x4321),
};

static gboolean filter_cb (GumAllocationTracker * tracker, gpointer address,
    guint size, gpointer user_data);