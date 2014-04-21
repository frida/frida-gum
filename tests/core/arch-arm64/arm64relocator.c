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
  TESTENTRY (b_should_be_rewritten)
  TESTENTRY (bl_should_be_rewritten)
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

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  GumArm64Mnemonic mnemonic;
  guint32 input[1];
  gsize input_length;
  guint32 expected_output[4];
  gsize expected_output_length;
  gsize pc_offset;
  gssize expected_pc_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestArm64RelocatorFixture * fixture);

TESTCASE (b_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM64_B,
    { 0x17ffff5a }, 1,  /* b #-664            */
    {
      0x58000050,       /* ldr x16, [pc, #8]  */
      0xd61f0200,       /* br x16             */
      0xffffffff,       /* <calculated PC     */
      0xffffffff        /*  goes here>        */
    }, 4,
    2, -664
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (bl_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM64_BL,
    { 0x97ffff5a }, 1,  /* bl #-664           */
    {
      0x5800005e,       /* ldr lr, [pc, #8]   */
      0xd63f03c0,       /* blr lr             */
      0xffffffff,       /* <calculated PC     */
      0xffffffff        /*  goes here>        */
    }, 4,
    2, -664
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestArm64RelocatorFixture * fixture)
{
  gsize i;
  guint32 calculated_pc;
  const GumArm64Instruction * insn = NULL;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT32_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT32_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  calculated_pc = fixture->rl.input_pc + bs->expected_pc_distance;
  *((guint64 *) (bs->expected_output + bs->pc_offset)) =
      GUINT64_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_arm64_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, bs->mnemonic);
  g_assert (gum_arm64_relocator_write_one (&fixture->rl));
  gum_arm64_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint32)), ==, 0);
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
