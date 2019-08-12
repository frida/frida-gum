/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64writer.h"

#include "testutil.h"

#include <string.h>

#define TESTCASE(NAME) \
    void test_arm64_writer_ ## NAME (TestArm64WriterFixture * fixture, \
        gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Arm64Writer", test_arm64_writer, NAME, \
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
  gum_arm64_writer_clear (&fixture->aw);
  g_free (fixture->output);
}

#define assert_output_n_equals(n, v) \
    g_assert_cmphex (GUINT32_FROM_LE (((guint32 *) fixture->output)[n]), ==, v)
#define assert_output_equals(v) \
    assert_output_n_equals (0, v)
