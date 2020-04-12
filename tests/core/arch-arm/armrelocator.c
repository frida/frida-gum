/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "armrelocator-fixture.c"

TESTLIST_BEGIN (armrelocator)
  TESTENTRY (one_to_one)
  TESTENTRY (pc_relative_ldr_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_negative_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_with_large_displacement_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_reg_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_reg_negative_should_fail)
  TESTENTRY (pc_relative_ldr_reg_shift_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_reg_preindex_should_fail)
  TESTENTRY (pc_relative_ldr_reg_postindex_should_fail)
  TESTENTRY (pc_relative_ldr_into_pc_should_be_rewritten)
  TESTENTRY (pc_relative_ldr_into_pc_with_shift_should_be_rewritten)
  TESTENTRY (pc_relative_add_should_be_rewritten)
  TESTENTRY (pc_relative_add_lsl_should_be_rewritten)
  TESTENTRY (pc_relative_add_imm_should_be_rewritten)
  TESTENTRY (b_imm_a1_positive_should_be_rewritten)
  TESTENTRY (b_imm_a1_negative_should_be_rewritten)
  TESTENTRY (bl_imm_a1_positive_should_be_rewritten)
  TESTENTRY (bl_imm_a1_negative_should_be_rewritten)
  TESTENTRY (blx_imm_a2_positive_should_be_rewritten)
  TESTENTRY (blx_imm_a2_negative_should_be_rewritten)
  TESTENTRY (pc_relative_mov_should_be_rewritten)
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

static void
show_disassembly (guint32 * input, gsize length);

TESTCASE (pc_relative_ldr_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59f3028 }, 1,          /* ldr r3, [pc, #0x28] */
    {
      0xe59f3004,               /* ldr r3, [pc, #4]  */
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

TESTCASE (pc_relative_ldr_negative_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe51f3028 }, 1,          /* ldr r3, [pc, #0x28] */
    {
      0xe59f3004,               /* ldr r3, [pc, #4]  */
      0xe2433028,               /* sub r3, r3, #0x28 */
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
      0xe59f3008,               /* ldr r3, [pc, #8]  */
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

TESTCASE (pc_relative_ldr_reg_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79f3003 }, 1,          /* ldr r3, [pc, r3] */
    {
      0xe2833c08,               /* add r3, r3, <0x08 >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, #8 */
      0xe5933000,               /* ldr r3, [r3]      */
    }, 3,
    -1, 0,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_reg_negative_should_fail)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe71f3003 }, 1,          /* ldr r3, [pc, -r3] */
    {
      0xe7f001f0,               /* udf #10 */
    }, 1,
    -1, 0,
    -1, -1
  };

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                        "relocation of ldr with subtracted register offset "
                        "not supported");
  branch_scenario_execute (&bs, fixture);

  g_test_assert_expected_messages ();
}

TESTCASE (pc_relative_ldr_reg_shift_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79f3103 }, 1,          /* ldr r3, [pc, r3, lsl #2] */
    {
      0xe1a03103,               /* lsl r3, r3, #2 */
      0xe2833c08,               /* add r3, r3, <0x08 >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, #8 */
      0xe5933000,               /* ldr r3, [r3]      */
    }, 10,
    -1, -1,
    -1, -1
  };

  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_reg_preindex_should_fail)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe7bf3003 }, 1,          /* ldr r3, [pc, r3]! */
    {
      0xe7f001f0,               /* udf #10 */
    }, 1,
    -1, -1,
    -1, -1
  };

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                        "relocation of ldr with pre/post-index not supported");
  branch_scenario_execute (&bs, fixture);

  g_test_assert_expected_messages ();
}

TESTCASE (pc_relative_ldr_reg_postindex_should_fail)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe69f3003 }, 1,          /* ldr r3, [pc], r3 */
    {
      0xe7f001f0,               /* udf #10 */
    }, 1,
    -1, -1,
    -1, -1
  };

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                        "relocation of ldr with pre/post-index not supported");
  branch_scenario_execute (&bs, fixture);

  g_test_assert_expected_messages ();
}

TESTCASE (pc_relative_ldr_into_pc_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe59ff004 }, 1,          /* ldr pc, [pc, #4] */
    {
      0xe92d0001,               /* stmdb sp!, {pc} */
      0xe59f0018,               /* ldr r0, [pc, #0x18] */
      0xe2800004,               /* add r0, r0, #4 */
      0xe5900000,               /* ldr r0, [r0]      */
      0xe58f0008,               /* str r0, [pc, #8]  */
      0xe8bd0001,               /* ldm sp!, {r0}     */
      0xe59ff000,               /* ldr pc, [pc]     */
      0xe7f001f8,               /* udf #0x18 */
      0xdeadface,
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 10,
    9, 0,
    -1, -1
  };

  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_ldr_into_pc_with_shift_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_LDR,
    { 0xe79ff103 }, 1,          /* ldr pc, [pc, r3, lsl #2] */
    {
      0xe92d0008,               /* stmdb sp!, {r3} */
      0xe1a03103,               /* lsl r3, r3, #2 */
      0xe2833c08,               /* add r3, r3, #8, #24 */
      0xe2833008,               /* add r3, r3, #8      */
      0xe5933000,               /* ldr r3, [r3]  */
      0xe58f3008,               /* str r3, [pc, #8]     */
      0xe8bd0008,               /* ldm sp!, {r3}    */
      0xe59ff000,               /* ldr pc, [pc]     */
      0xe7f001f8,               /* udf #0x18 */
      0xdeadface,
    }, 10,
    -1, -1,
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
      0xe2833c08,               /* add r3, r3, <0xXX >>> 0xc*2> */
      0xe2833008,               /* add r3, r3, 0xXX */
    }, 2,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_lsl_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe08ff101 }, 1,          /* add pc, pc, r1 lsl #2  */
    {
      0xe92d0002,               /* stmdb sp!, {r1} */
      0xe1a01101,               /* mov r1, r1, lsl #2 */
      0xe2811c08,               /* add r1, r1, <0xXX >>> 0xc*2> */
      0xe2811008,               /* add r1, r1, 0xXX */
      0xe58f1008,               /* str r1, [pc, #8] */
      0xe8bd0002,               /* ldm sp!, {r1} */
      0xe59ff000,               /* ldr pc, [pc] */
      0xe7f001f8,               /* udf #0x18 */
      0xdeadface,
    }, 9,
    -1, -1,
    -1, -1
  };
  branch_scenario_execute (&bs, fixture);
}

TESTCASE (pc_relative_add_imm_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_ADD,
    { 0xe28f3008 }, 1,          /* add r3, pc, #8   */
    {
      0xe59f3000,               /* ldr r3, [pc] */
      0xe2833008,               /* add r3, r3, 0xXX */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    2, 0,
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

TESTCASE (pc_relative_mov_should_be_rewritten)
{
  BranchScenario bs = {
    ARM_INS_MOV,
    { 0xe1a0e00f }, 1,          /* mov pc, lr        */
    {
      0xe51fe004,               /* ldr lr, [pc, #-4]  */
      0xffffffff                /* <calculated PC    */
                                /*  goes here>       */
    }, 2,
    1, 0,
    -1, -1
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

    g_print ("\n\nInput:\n\n");
    g_print ("0x%llx: %s %s\n", insn->address, insn->mnemonic, insn->op_str);

    g_print ("\n\nExpected:\n\n");
    show_disassembly (bs->expected_output, bs->expected_output_length);

    g_print ("\n\nWrong:\n\n");
    show_disassembly ((guint32 *)fixture->output, bs->expected_output_length);
  }

  g_assert_true (same_content);
}

static void
show_disassembly (guint32 * input, gsize length)
{
  csh capstone;
  cs_err err;
  cs_insn * insn = NULL;
  gsize idx;

  err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
  g_assert (err == CS_ERR_OK);
  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert (err == CS_ERR_OK);

  for (idx = 0; idx < length; idx++)
  {
    cs_disasm (capstone, (guint8 *)&input[idx], 4,
        GPOINTER_TO_SIZE (&input[idx]), 1, &insn);

    g_print ("0x%llx: %s %s\n", insn->address, insn->mnemonic, insn->op_str);
  }

  cs_close (&capstone);
}