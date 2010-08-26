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

#include "gumx86writer.h"

#include "testutil.h"

#include <string.h>

#define CODEWRITER_TESTCASE(NAME) \
    void test_code_writer_ ## NAME ( \
        TestCodeWriterFixture * fixture, gconstpointer data)
#define CODEWRITER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/CodeWriter", test_code_writer, NAME, \
        TestCodeWriterFixture)

typedef struct _TestCodeWriterFixture
{
  guint8 output[32];
  GumX86Writer cw;
} TestCodeWriterFixture;

static void
test_code_writer_fixture_setup (TestCodeWriterFixture * fixture,
                                gconstpointer data)
{
  gum_x86_writer_init (&fixture->cw, fixture->output);

  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_AMD64);
}

static void
test_code_writer_fixture_teardown (TestCodeWriterFixture * fixture,
                                   gconstpointer data)
{
  gum_x86_writer_free (&fixture->cw);
}

static void
test_code_writer_fixture_assert_output_equals (TestCodeWriterFixture * fixture,
                                               const guint8 * expected_code,
                                               guint expected_length)
{
  gboolean same_length, same_content;

  gum_x86_writer_flush (&fixture->cw);

  same_length = (gum_x86_writer_offset (&fixture->cw) == expected_length);
  if (same_length)
  {
    same_content =
        memcmp (fixture->output, expected_code, expected_length) == 0;
  }
  else
  {
    same_content = FALSE;
  }

  if (!same_length || !same_content)
  {
    gchar * diff;

    diff = test_util_diff_binary (expected_code, expected_length,
        fixture->output, gum_x86_writer_offset (&fixture->cw));
    g_print ("\n\nGenerated code is not equal to expected code:\n\n%s\n",
        diff);
    g_free (diff);
  }

  g_assert (same_length);
  g_assert (same_content);
}

#define assert_output_equals(e) test_code_writer_fixture_assert_output_equals (fixture, e, sizeof (e))
