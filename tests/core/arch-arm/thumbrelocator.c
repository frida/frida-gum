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

#include "thumbrelocator-fixture.c"

TEST_LIST_BEGIN (thumbrelocator)
  RELOCATOR_TESTENTRY (one_to_one)
  RELOCATOR_TESTENTRY (handle_extended_instructions)

  RELOCATOR_TESTENTRY (ldrpc_should_be_rewritten)
  RELOCATOR_TESTENTRY (addh_should_be_rewritten_if_pc_relative)
TEST_LIST_END ()

RELOCATOR_TESTCASE (one_to_one)
{
  const guint16 input[] = {
    0xb580,                   /* push {r7, lr}  */
    0xaf00,                   /* add r7, sp, #0 */
  };
  const GumArmInstruction * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_ADDSP);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (2);

  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 2, input + 1, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert (!gum_thumb_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (handle_extended_instructions)
{
  const guint16 input[] = {
    0xf241, 0x3037,           /* movw r0, #4919 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert (!gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input)), ==, 0);
}

RELOCATOR_TESTCASE (ldrpc_should_be_rewritten)
{
  const guint16 input[] = {
    0x4a03,                   /* ldr r2, [pc, #12] */
  };
  guint16 expected_output[] = {
    0x4a00,                   /* ldr r2, [pc, #0] */
    0x6812,                   /* ldr r2, r2       */
    0xffff,                   /* <calculated PC   */
    0xffff,                   /*  goes here>      */
  };
  gsize calculated_pc;
  const GumArmInstruction * insn = NULL;

  calculated_pc = GPOINTER_TO_SIZE (input) + 2 + 12;
  if (calculated_pc % 4 != 0)
    calculated_pc += 2;
  *((gsize *) (expected_output + 2)) = calculated_pc;

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_LDRPC);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (addh_should_be_rewritten_if_pc_relative)
{
  const guint16 input[] = {
    0x447a,                   /* add r2, pc       */
  };
  guint16 expected_output[] = {
    0xb401,                   /* push {r0}        */
    0x4801,                   /* ldr r0, [pc, #4] */
    0x1812,                   /* adds r2, r2, r0  */
    0xbc01,                   /* pop {r0}         */
    0xffff,                   /* <calculated PC   */
    0xffff,                   /*  goes here>      */
  };
  gsize calculated_pc;
  const GumArmInstruction * insn = NULL;

  calculated_pc = GPOINTER_TO_SIZE (input) + 2;
  if (calculated_pc % 4 != 0)
    calculated_pc += 2;
  *((gsize *) (expected_output + 4)) = calculated_pc;

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_ADDH);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}
