/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumthumbwriter.h"

#include "testutil.h"

#include <string.h>

#define THUMBWRITER_TESTCASE(NAME) \
    void test_thumb_writer_ ## NAME ( \
        TestThumbWriterFixture * fixture, gconstpointer data)
#define THUMBWRITER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/ThumbWriter", test_thumb_writer, NAME, \
        TestThumbWriterFixture)

typedef struct _TestThumbWriterFixture
{
  guint16 output[16];
  GumThumbWriter tw;
} TestThumbWriterFixture;

static void
test_thumb_writer_fixture_setup (TestThumbWriterFixture * fixture,
                                 gconstpointer data)
{
  gum_thumb_writer_init (&fixture->tw, fixture->output);
}

static void
test_thumb_writer_fixture_teardown (TestThumbWriterFixture * fixture,
                                    gconstpointer data)
{
  gum_thumb_writer_free (&fixture->tw);
}

#define assert_output_n_equals(n, v) \
    g_assert_cmphex (GUINT16_FROM_LE (fixture->output[n]), ==, v)
#define assert_output_equals(v) \
    assert_output_n_equals (0, v)
