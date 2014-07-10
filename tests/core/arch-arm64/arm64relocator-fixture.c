/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64relocator.h"

#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define TESTCASE(NAME) \
    void test_arm64_relocator_ ## NAME ( \
        TestArm64RelocatorFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Arm64Relocator", test_arm64_relocator, \
        NAME, TestArm64RelocatorFixture)

#define TEST_OUTBUF_SIZE 32

typedef struct _TestArm64RelocatorFixture
{
  guint8 * output;
  GumArm64Writer aw;
  GumArm64Relocator rl;
} TestArm64RelocatorFixture;

static void
test_arm64_relocator_fixture_setup (TestArm64RelocatorFixture * fixture,
                                    gconstpointer data)
{
  fixture->output = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RW);

  gum_arm64_writer_init (&fixture->aw, fixture->output);
  fixture->aw.pc = 1024;
}

static void
test_arm64_relocator_fixture_teardown (TestArm64RelocatorFixture * fixture,
                                       gconstpointer data)
{
  gum_arm64_relocator_free (&fixture->rl);
  gum_arm64_writer_free (&fixture->aw);
  gum_free_pages (fixture->output);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_arm64_relocator_init (&fixture->rl, CODE, &fixture->aw); \
    fixture->rl.input_pc = 2048

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)
