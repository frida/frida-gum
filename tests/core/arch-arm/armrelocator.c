/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "armrelocator-fixture.c"

TEST_LIST_BEGIN (armrelocator)
  RELOCATOR_TESTENTRY (one_to_one)
  RELOCATOR_TESTENTRY (b_imm_a1_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (b_imm_a1_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (bl_imm_a1_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (bl_imm_a1_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (blx_imm_a2_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (blx_imm_a2_negative_should_be_rewritten)
TEST_LIST_END ()

RELOCATOR_TESTCASE (one_to_one)
{
  const guint32 input[] = {
    0xe1a0c00d,               /* mov ip, sp    */
    0xe92d0030,               /* push {r4, r5} */
  };
  const GumArmInstruction * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_MOV);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 8);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 4, input + 1, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (8);

  g_assert (!gum_arm_relocator_write_one (&fixture->rl));
}

/*
 * Branch instruction coverage based on DDI0487A_b_armv8_arm.pdf
 *
 * B imm (F7.1.18)
 * [x] A1
 *
 * BL, BLX imm (F7.1.25)
 * [x] A1
 * [x] A2
 */

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  GumArmMnemonic mnemonic;
  guint32 input[1];
  gsize input_length;
  guint32 expected_output[4];
  gsize expected_output_length;
  gsize pc_offset;
  gssize expected_pc_distance;
  gssize lr_offset;
  gssize expected_lr_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestArmRelocatorFixture * fixture);

RELOCATOR_TESTCASE (b_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_A1,
    { 0xea000001 }, 1,          /* b pc + 4          */
    {
      0xe51ff004,               /* ldr pc, [pc, #-4] */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, 4,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (b_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_A1,
    { 0xeaffffff }, 1,          /* b pc - 4          */
    {
      0xe51ff004,               /* ldr pc, [pc, #-4] */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, -4,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (bl_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BL_IMM_A1,
    { 0xeb000001 }, 1,          /* bl pc + 4         */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, 4,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (bl_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BL_IMM_A1,
    { 0xebffffff }, 1,          /* bl pc - 4         */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, -4,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (blx_imm_a2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BLX_IMM_A2,
    { 0xfb000001 }, 1,          /* blx pc + 6        */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, 7,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (blx_imm_a2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BLX_IMM_A2,
    { 0xfaffffff }, 1,          /* blx pc - 4        */
    {
      0xe59fe000,               /* ldr lr, [pc, #0]  */
      0xe59ff000,               /* ldr pc, [pc, #0]  */
      0xffffffff,               /* <calculated LR    */
                                /*  goes here>       */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, -3,
    2, 2
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestArmRelocatorFixture * fixture)
{
  gsize calculated_pc;
  const GumArmInstruction * insn = NULL;

  calculated_pc = GPOINTER_TO_SIZE (bs->input) + 8 + bs->expected_pc_distance;
  *((gsize *) (bs->expected_output + bs->pc_offset)) = calculated_pc;

  if (bs->lr_offset != -1)
  {
    gsize calculated_lr;

    calculated_lr = GPOINTER_TO_SIZE (fixture->output) +
        (bs->expected_lr_distance * sizeof (guint32));
    *((gsize *) (bs->expected_output + bs->lr_offset)) = calculated_lr;
  }

  SETUP_RELOCATOR_WITH (bs->input);

  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, bs->mnemonic);
  g_assert (gum_arm_relocator_write_one (&fixture->rl));
  gum_arm_writer_flush (&fixture->aw);
  g_assert_cmpint (memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint32)), ==, 0);
}
