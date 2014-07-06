/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumarm64writer.h"

#include "testutil.h"

#include <string.h>

#define TESTCASE(NAME) \
    void test_arm64_writer_ ## NAME (TestArm64WriterFixture * fixture, \
        gconstpointer data)
#define TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Arm64Writer", test_arm64_writer, NAME, \
        TestArm64WriterFixture)

typedef struct _TestArm64WriterFixture
{
  gpointer output;
  GumArm64Writer aw;
} TestArm64WriterFixture;

static void
test_arm64_writer_fixture_setup (TestArm64WriterFixture * fixture,
                                 gconstpointer data)
{
  fixture->output = g_malloc (16 * sizeof (guint32));
  gum_arm64_writer_init (&fixture->aw, fixture->output);
}

static void
test_arm64_writer_fixture_teardown (TestArm64WriterFixture * fixture,
                                    gconstpointer data)
{
  gum_arm64_writer_free (&fixture->aw);
  g_free (fixture->output);
}

#define assert_output_n_equals(n, v) \
    g_assert_cmphex (GUINT32_FROM_LE (((guint32 *) fixture->output)[n]), ==, v)
#define assert_output_equals(v) \
    assert_output_n_equals (0, v)
