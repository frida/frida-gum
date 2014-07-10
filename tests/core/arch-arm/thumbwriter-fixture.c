/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
  gpointer output;
  GumThumbWriter tw;
} TestThumbWriterFixture;

static void
test_thumb_writer_fixture_setup (TestThumbWriterFixture * fixture,
                                 gconstpointer data)
{
  fixture->output = g_malloc (16 * 2);
  gum_thumb_writer_init (&fixture->tw, fixture->output);
}

static void
test_thumb_writer_fixture_teardown (TestThumbWriterFixture * fixture,
                                    gconstpointer data)
{
  gum_thumb_writer_free (&fixture->tw);
  g_free (fixture->output);
}

#define assert_output_n_equals(n, v) \
    g_assert_cmphex (GUINT16_FROM_LE (((guint16 *) fixture->output)[n]), ==, v)
#define assert_output_equals(v) \
    assert_output_n_equals (0, v)
