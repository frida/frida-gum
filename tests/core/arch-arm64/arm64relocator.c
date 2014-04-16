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

#include "arm64relocator-fixture.c"

TEST_LIST_BEGIN (arm64relocator)
  TESTENTRY (one_to_one)
  TESTENTRY (adr_should_be_rewritten)
  TESTENTRY (adrp_should_be_rewritten)
  TESTENTRY (eob_and_eoi_on_ret)
TEST_LIST_END ()

TESTCASE (one_to_one)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xe1a0c00d), /* mov ip, sp    */
    GUINT32_TO_LE (0xe92d0030), /* push {r4, r5} */
  };
  const GumArm64Instruction * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 8);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert (gum_arm64_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert (gum_arm64_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 4, input + 1, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (8);

  g_assert (!gum_arm64_relocator_write_one (&fixture->rl));
}

TESTCASE (adr_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0x5000a721)  /* adr x1, 0x14e6     */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000021), /* ldr x1, [pc, #4]   */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[3 * sizeof (guint32)];
  guint64 calculated_pc;
  const GumArm64Instruction * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 0x14e6;
  *((guint64 *) (expected_output + 4)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM64_ADR);
  g_assert (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (adrp_should_be_rewritten)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xd000a723)  /* adrp x3, 0x14e6000 */
  };
  const guint32 expected_output_instructions[] = {
    GUINT32_TO_LE (0x58000023), /* ldr x3, [pc, #4]   */
    0xffffffff,                 /* <calculated PC     */
    0xffffffff                  /*  goes here>        */
  };
  gchar expected_output[3 * sizeof (guint32)];
  guint64 calculated_pc;
  const GumArm64Instruction * insn;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 0x14e6000;
  *((guint64 *) (expected_output + 4)) = GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM64_ADRP);
  g_assert (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

TESTCASE (eob_and_eoi_on_ret)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xd65f03c0)  /* ret */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert (gum_arm64_relocator_eob (&fixture->rl));
  g_assert (gum_arm64_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, NULL), ==, 0);
}
