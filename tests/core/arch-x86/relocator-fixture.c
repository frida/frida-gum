/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "testutil.h"

#include "gummemory.h"
#include "gumrelocator.h"

#include <string.h>

#define RELOCATOR_TESTCASE(NAME) \
    void test_relocator_ ## NAME ( \
        TestRelocatorFixture * fixture, gconstpointer data)
#define RELOCATOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE (Relocator, test_relocator, NAME, \
        TestRelocatorFixture)

#define TEST_OUTBUF_SIZE 32

typedef struct _TestRelocatorFixture
{
  guint8 * output;
  GumCodeWriter cw;
  GumRelocator rl;
} TestRelocatorFixture;

static void
test_relocator_fixture_setup (TestRelocatorFixture * fixture,
                              gconstpointer data)
{
  fixture->output = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  memset (fixture->output, 0, gum_query_page_size ());
  gum_code_writer_init (&fixture->cw, fixture->output);
}

static void
test_relocator_fixture_teardown (TestRelocatorFixture * fixture,
                                 gconstpointer data)
{
  gum_relocator_free (&fixture->rl);
  gum_code_writer_free (&fixture->cw);
  gum_free_pages (fixture->output);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_relocator_init (&fixture->rl, CODE, &fixture->cw)

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)
