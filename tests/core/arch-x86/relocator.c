/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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
  guint8 output[TEST_OUTBUF_SIZE];
  GumCodeWriter cw;
  GumRelocator rl;
} TestRelocatorFixture;

static void
test_relocator_fixture_setup (TestRelocatorFixture * fixture,
                              gconstpointer data)
{
  memset (fixture->output, 0, sizeof (fixture->output));
  gum_code_writer_init (&fixture->cw, fixture->output);
}

static void
test_relocator_fixture_teardown (TestRelocatorFixture * fixture,
                                 gconstpointer data)
{
  gum_relocator_free (&fixture->rl);
  gum_code_writer_free (&fixture->cw);
}

static const guint8 cleared_outbuf[TEST_OUTBUF_SIZE] = { 0, };

#define SETUP_RELOCATOR_WITH(CODE) \
    gum_relocator_init (&fixture->rl, CODE, &fixture->cw)

#define assert_outbuf_still_zeroed_from_offset(OFF) \
    g_assert_cmpint (memcmp (fixture->output + OFF, cleared_outbuf + OFF, \
        sizeof (cleared_outbuf) - OFF), ==, 0)

TEST_LIST_BEGIN (relocator)
  RELOCATOR_TESTENTRY (one_to_one)
  RELOCATOR_TESTENTRY (call_near_relative)
  RELOCATOR_TESTENTRY (call_near_indirect)
  RELOCATOR_TESTENTRY (jmp_short_outside_block)
  RELOCATOR_TESTENTRY (jmp_near_outside_block)
  RELOCATOR_TESTENTRY (jcc_short_within_block);
  RELOCATOR_TESTENTRY (jcc_short_outside_block);
  RELOCATOR_TESTENTRY (peek_next_write);
  RELOCATOR_TESTENTRY (skip_instruction);
  RELOCATOR_TESTENTRY (eob_and_eoi_on_jmp)
  RELOCATOR_TESTENTRY (eob_and_eoi_on_call)
  RELOCATOR_TESTENTRY (eob_and_eoi_on_ret)
  RELOCATOR_TESTENTRY (eob_but_not_eoi_on_jcc)
TEST_LIST_END ()

RELOCATOR_TESTCASE (one_to_one)
{
  const guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
  };
  const ud_t * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, &insn), ==, 1);
  g_assert_cmpint (insn->mnemonic, ==, UD_Ipush);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, &insn), ==, 3);
  g_assert_cmpint (insn->mnemonic, ==, UD_Imov);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert (gum_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 1), ==, 0);
  assert_outbuf_still_zeroed_from_offset (1);

  g_assert (gum_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 1, input + 1, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (3);

  g_assert (!gum_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (call_near_relative)
{
  const guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
    0xe8, 0x04, 0x00, 0x00, 0x00, /* call dummy   */
    0x8b, 0xe5,                   /* mov esp, ebp */
    0x5d,                         /* pop ebp      */
    0xc3,                         /* retn         */

/* dummy:                                         */
    0xc3                          /* retn         */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 8);

  gum_relocator_write_all (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output + 3, input + 3, 5), !=, 0);
  reloc_distance = *((gint32 *) (fixture->output + 4));
  expected_distance =
      ((gssize) (input + 12)) - ((gssize) (fixture->output + 8));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (call_near_indirect)
{
  const guint8 input[] = {
    0xff, 0x15, 0x78, 0x56, 0x34, 0x12 /* call ds:012345678h */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 6);
  gum_relocator_write_one (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output, input, 6), ==, 0);
}

RELOCATOR_TESTCASE (jmp_short_outside_block)
{
  const guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==, 5);

  g_assert_cmphex (fixture->output[0], !=, input[0]);
  g_assert_cmphex (fixture->output[0], ==, 0xe9);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance =
      ((gssize) (input + 2 + 1)) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (jmp_near_outside_block)
{
  const guint8 input[] = {
    0xe9, 0x01, 0x00, 0x00, 0x00, /* jmp +1 */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==, sizeof (input));

  g_assert_cmphex (fixture->output[0], ==, input[0]);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance =
      ((gssize) (input + 5 + 1)) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (jcc_short_within_block)
{
  const guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x01,                         /* jnz beach   */
    0x40,                               /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 10);
  gum_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==,
      sizeof(input));

  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_code_writer_put_inc_eax (&fixture->cw);
  gum_relocator_write_one (&fixture->rl);

  gum_code_writer_flush (&fixture->cw);

  /* output should have one extra instruction of 1 byte */
  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==,
      sizeof (input) + 1);

  /* the first 9 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, 9), ==, 0);

  /* the jnz offset should be adjusted to account for the extra instruction */
  g_assert_cmpint ((gint8) fixture->output[9], ==, ((gint8) input[9]) + 1);

  /* the rest should be the same */
  g_assert_cmpint (memcmp (fixture->output + 11, input + 10, 2), ==, 0);
}

RELOCATOR_TESTCASE (jcc_short_outside_block)
{
  const guint8 input[] = {
    0x75, 0xfd, /* jnz -3 */
    0xc3        /* retn   */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_write_all (&fixture->rl);

  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==, 6 + 1);
  g_assert_cmphex (fixture->output[0], ==, 0x0f);
  g_assert_cmphex (fixture->output[1], ==, 0x85);
  g_assert_cmpint (*((gint32 *) (fixture->output + 2)), ==,
      (gssize) (input - 1) - (gssize) (fixture->output + 6));
  g_assert_cmphex (fixture->output[6], ==, input[2]);
}

RELOCATOR_TESTCASE (peek_next_write)
{
  const guint8 input[] = {
    0x31, 0xc0, /* xor eax,eax */
    0x40,       /* inc eax     */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_relocator_read_one (&fixture->rl, NULL);
  gum_relocator_read_one (&fixture->rl, NULL);

  g_assert_cmpint (gum_relocator_peek_next_write_insn (&fixture->rl)->mnemonic,
      ==, UD_Ixor);
  gum_relocator_write_one (&fixture->rl);
  g_assert_cmpint (gum_relocator_peek_next_write_insn (&fixture->rl)->mnemonic,
      ==, UD_Iinc);
  g_assert_cmpint (gum_relocator_peek_next_write_insn (&fixture->rl)->mnemonic,
      ==, UD_Iinc);
  g_assert (gum_relocator_peek_next_write_source (&fixture->rl)
      == input + 2);
  g_assert (gum_relocator_write_one (&fixture->rl));
  g_assert (gum_relocator_peek_next_write_insn (&fixture->rl) == NULL);
  g_assert (gum_relocator_peek_next_write_source (&fixture->rl) == NULL);
  g_assert (!gum_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (skip_instruction)
{
  const guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x01,                         /* jnz beach   */
    0x40,                               /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  while (!gum_relocator_eoi (&fixture->rl))
    gum_relocator_read_one (&fixture->rl, NULL);

  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_relocator_write_one (&fixture->rl);
  gum_relocator_skip_one (&fixture->rl); /* skip retn */
  gum_code_writer_put_inc_eax (&fixture->cw); /* put "inc eax" there instead */

  gum_code_writer_flush (&fixture->cw);

  /* output should be of same size */
  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==, sizeof (input));

  /* the first n - 1 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input) - 1), ==, 0);
}

RELOCATOR_TESTCASE (eob_and_eoi_on_jmp)
{
  const guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_relocator_eob (&fixture->rl));
  g_assert (gum_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_and_eoi_on_call)
{
  const guint8 input[] = {
    0xe8, 0x42, 0x00, 0x00, 0x00  /* jmp +0x42 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert (gum_relocator_eob (&fixture->rl));
  g_assert (gum_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_and_eoi_on_ret)
{
  const guint8 input[] = {
    0xc2, 0x04, 0x00  /* retn 4 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert (gum_relocator_eob (&fixture->rl));
  g_assert (gum_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_but_not_eoi_on_jcc)
{
  const guint8 input[] = {
    0x74, 0x01, /* jz +1  */
    0xc3        /* ret    */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_relocator_eob (&fixture->rl));
  g_assert (!gum_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert (gum_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_relocator_read_one (&fixture->rl, NULL), ==, 0);
}
