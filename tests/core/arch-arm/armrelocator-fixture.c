/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumarmrelocator.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define RELOCATOR_TESTCASE(NAME) \
    void test_arm_relocator_ ## NAME ( \
        TestArmRelocatorFixture * fixture, gconstpointer data)
#define RELOCATOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/ArmRelocator", test_arm_relocator, \
        NAME, TestArmRelocatorFixture)

#define TEST_OUTBUF_SIZE 32

typedef struct _TestArmRelocatorFixture
{
  guint8 * output;
  GumArmWriter aw;
  GumArmRelocator rl;
} TestArmRelocatorFixture;

static void
test_arm_relocator_fixture_setup (TestArmRelocatorFixture * fixture,
                                  gconstpointer data)
{
  fixture->output = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RW);

  gum_arm_writer_init (&fixture->aw, fixture->output);
  fixture->aw.pc = 1024;
}

static void
test_arm_relocator_fixture_teardown (TestArmRelocatorFixture * fixture,
                                     gconstpointer data)
{
  gum_arm_relocator_free (&fixture->rl);
  gum_arm_writer_free (&fixture->aw);
  gum_free_pages (fixture->output);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_arm_relocator_init (&fixture->rl, CODE, &fixture->aw); \
    fixture->rl.input_pc = 2048

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)
