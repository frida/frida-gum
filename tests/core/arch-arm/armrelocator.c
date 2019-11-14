/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "armrelocator-fixture.c"

TESTLIST_BEGIN (armrelocator)
  TESTENTRY (one_to_one)
  TESTENTRY (pc_relative_ldr_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_with_large_displacement_should_be_rewritten)
  TESTENTRY (pc_relative_add_should_be_rewritten)
  TESTENTRY (b_imm_a1_positive_should_be_rewritten)
  TESTENTRY (b_imm_a1_negative_should_be_rewritten)
  TESTENTRY (bl_imm_a1_positive_should_be_rewritten)
  TESTENTRY (bl_imm_a1_negative_should_be_rewritten)
  TESTENTRY (blx_imm_a2_positive_should_be_rewritten)
  TESTENTRY (blx_imm_a2_negative_should_be_rewritten)
TESTLIST_END ()

TESTCASE (one_to_one)
{
  const guint32 input[] = {
    GUINT32_TO_LE (0xe1a0c00d), /* mov ip, sp    */
    GUINT32_TO_LE (0xe92d0030), /* push {r4, r5} */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, ARM_INS_MOV);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 8);
  g_assert_cmpint (insn->id, ==, ARM_INS_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 4, input + 1, 4), ==, 0);
  assert_outbuf_still_zeroed_from_offset (8);

  g_assert_false (gum_arm_relocator_write_one (&fixture->rl));
}

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  guint instruction_id;
  guint32 input[1];
  gsize input_length;
  guint32 expected_output[10];
  gsize expected_output_length;
  gssize pc_offset;
  gssize expected_pc_distance;
  gssize lr_offset;
  gssize expected_lr_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestArmRelocatorFixture * fixture);

TESTCASE (pc_relative_ldr_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59f3028 }, 1,          /* ldr r3, [pc, #0x28] */
    {
      0xe59f3004,               /* ldr lr, [pc, #4]  */
      0xe2833028,               /* add r3, r3, #0x28 */
      0xe5933000,               /* ldr r3, [r3]      */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 4,
    3, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_with_large_displacement_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59f338c }, 1,          /* ldr r3, [pc, #0x38c] */
    {
      0xe59f3008,               /* ldr lr, [pc, #8]  */
      0xe2833c03,               /* add r3, r3, <0x03 >>> 0xc*2> */
      0xe283308c,               /* add r3, r3, #0x8c */
      0xe5933000,               /* ldr r3, [r3]      */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 5,
    4, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08f3003 }, 1,          /* add r3, pc, r3   */
    {
      0xe2833008,               /* add r3, r3, 0xXX */
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833800,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833400,               /* add r3, r3, <0xXX >>> 0xc*2> */
    }, 4,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (b_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
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

TESTCASE (b_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_B,
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

TESTCASE (bl_imm_a1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
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

TESTCASE (bl_imm_a1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BL,
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

TESTCASE (blx_imm_a2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
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

TESTCASE (blx_imm_a2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_BLX,
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
  gsize i;
  const cs_insn * insn = NULL;
  gboolean same_content;
  gchar * diff;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT32_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT32_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  if (bs->pc_offset != -1)
  {
    guint32 calculated_pc;

    calculated_pc = fixture->rl.input_pc + 8 + bs->expected_pc_distance;
    *((guint32 *) (bs->expected_output + bs->pc_offset)) =
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
        GUINT32_TO_LE (calculated_pc);
#else
        GUINT32_TO_BE (calculated_pc);
#endif
  }

  if (bs->lr_offset != -1)
  {
    guint32 calculated_lr;

    calculated_lr = (guint32) (fixture->aw.pc +
        (bs->expected_lr_distance * sizeof (guint32)));
    *((guint32 *) (bs->expected_output + bs->lr_offset)) =
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
        GUINT32_TO_LE (calculated_lr);
#else
        GUINT32_TO_BE (calculated_lr);
#endif
  }

  g_assert_cmpuint (gum_arm_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->id, ==, bs->instruction_id);
  g_assert_true (gum_arm_relocator_write_one (&fixture->rl));
  gum_arm_writer_flush (&fixture->aw);

  same_content = memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint32)) == 0;

  diff = test_util_diff_binary (
      (guint8 *) bs->expected_output,
      bs->expected_output_length * sizeof (guint32),
      fixture->output,
      bs->expected_output_length * sizeof (guint32));

  if (!same_content)
  {
    g_print ("\n\nGenerated code is not equal to expected code:\n\n%s\n",
        diff);
  }

  g_assert_true (same_content);
}
