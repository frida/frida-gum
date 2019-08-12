/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthumbrelocator.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define TESTCASE(NAME) \
    void test_thumb_relocator_ ## NAME ( \
        TestThumbRelocatorFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/ThumbRelocator", test_thumb_relocator, \
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
  fixture->tw.pc = 1024;
}

static void
test_thumb_relocator_fixture_teardown (TestThumbRelocatorFixture * fixture,
                                       gconstpointer data)
{
  gum_thumb_relocator_clear (&fixture->rl);
  gum_thumb_writer_clear (&fixture->tw);
  gum_free_pages (fixture->output);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_thumb_relocator_init (&fixture->rl, CODE, &fixture->tw); \
    fixture->rl.input_pc = 2048

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)
