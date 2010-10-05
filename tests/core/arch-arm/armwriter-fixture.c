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

#include "gumarmwriter.h"

#include "testutil.h"

#include <string.h>

#define ARMWRITER_TESTCASE(NAME) \
    void test_arm_writer_ ## NAME ( \
        TestArmWriterFixture * fixture, gconstpointer data)
#define ARMWRITER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/ArmWriter", test_arm_writer, NAME, \
        TestArmWriterFixture)

typedef struct _TestArmWriterFixture
{
  guint32 output[16];
  GumArmWriter tw;
} TestArmWriterFixture;

static void
test_arm_writer_fixture_setup (TestArmWriterFixture * fixture,
                               gconstpointer data)
{
  gum_arm_writer_init (&fixture->tw, fixture->output);
}

static void
test_arm_writer_fixture_teardown (TestArmWriterFixture * fixture,
                                  gconstpointer data)
{
  gum_arm_writer_free (&fixture->tw);
}

#define assert_output_n_equals(n, v) \
    g_assert_cmphex (GUINT32_FROM_LE (fixture->output[n]), ==, v)
#define assert_output_equals(v) \
    assert_output_n_equals (0, v)
