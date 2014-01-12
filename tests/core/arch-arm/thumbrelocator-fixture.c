/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumthumbrelocator.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define RELOCATOR_TESTCASE(NAME) \
    void test_thumb_relocator_ ## NAME ( \
        TestThumbRelocatorFixture * fixture, gconstpointer data)
#define RELOCATOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/ThumbRelocator", test_thumb_relocator, \
        NAME, TestThumbRelocatorFixture)

#define TEST_OUTBUF_SIZE 32

typedef struct _TestThumbRelocatorFixture
{
  guint8 * output;
  GumThumbWriter tw;
  GumThumbRelocator rl;
} TestThumbRelocatorFixture;

static void
test_thumb_relocator_fixture_setup (TestThumbRelocatorFixture * fixture,
                                    gconstpointer data)
{
  fixture->output = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RW);

  gum_thumb_writer_init (&fixture->tw, fixture->output);
}

static void
test_thumb_relocator_fixture_teardown (TestThumbRelocatorFixture * fixture,
                                       gconstpointer data)
{
  gum_thumb_relocator_free (&fixture->rl);
  gum_thumb_writer_free (&fixture->tw);
  gum_free_pages (fixture->output);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_thumb_relocator_init (&fixture->rl, CODE, &fixture->tw)

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)
