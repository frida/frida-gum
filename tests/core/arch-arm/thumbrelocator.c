/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "thumbrelocator-fixture.c"

TEST_LIST_BEGIN (thumbrelocator)
  RELOCATOR_TESTENTRY (one_to_one)
  RELOCATOR_TESTENTRY (handle_extended_instructions)

  RELOCATOR_TESTENTRY (ldrpc_t1_should_be_rewritten)
  RELOCATOR_TESTENTRY (ldrpc_t2_should_be_rewritten)
  RELOCATOR_TESTENTRY (addh_should_be_rewritten_if_pc_relative)
  RELOCATOR_TESTENTRY (b_imm_t2_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (b_imm_t2_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (b_imm_t4_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (b_imm_t4_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (bl_imm_t1_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (bl_imm_t1_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (blx_imm_t2_positive_should_be_rewritten)
  RELOCATOR_TESTENTRY (blx_imm_t2_negative_should_be_rewritten)
  RELOCATOR_TESTENTRY (cbz_should_be_rewritten)
  RELOCATOR_TESTENTRY (eob_and_eoi_on_ret)
TEST_LIST_END ()

RELOCATOR_TESTCASE (one_to_one)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb580), /* push {r7, lr}  */
    GUINT16_TO_LE (0xaf00), /* add r7, sp, #0 */
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
  g_assert_cmpint (memcmp (((guint8 *) fixture->output) + 2, input + 1, 2),
      ==, 0);
  assert_outbuf_still_zeroed_from_offset (4);

  g_assert (!gum_thumb_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (handle_extended_instructions)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xe92d), GUINT16_TO_LE (0x4ff0), /* stmdb sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr} */
    GUINT16_TO_LE (0xb580), /* push {r7, lr}  */
    GUINT16_TO_LE (0xf241), GUINT16_TO_LE (0x3037), /* movw r0, #4919 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 6);
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 10);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert (!gum_thumb_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input)), ==, 0);
}

RELOCATOR_TESTCASE (ldrpc_t1_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x4a03), /* ldr r2, [pc, #12] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0x4a00), /* ldr r2, [pc, #0] */
    GUINT16_TO_LE (0x6812), /* ldr r2, r2       */
    GUINT16_TO_LE (0xffff), /* <calculated PC   */
    GUINT16_TO_LE (0xffff), /*  goes here>      */
  };
  gchar expected_output[4 * sizeof (guint16)];

  guint32 calculated_pc;
  const GumArmInstruction * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = (fixture->rl.input_pc + 4 + 12) & ~(4 - 1);
  *((guint32 *) (expected_output + 4)) = GUINT32_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_LDRPC_T1);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (ldrpc_t2_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xf8df), GUINT16_TO_LE (0x2768) /* ldr.w r2, [pc, #1896] */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0x4a00), /* ldr r2, [pc, #0] */
    GUINT16_TO_LE (0x6812), /* ldr r2, r2       */
    GUINT16_TO_LE (0xffff), /* <calculated PC   */
    GUINT16_TO_LE (0xffff), /*  goes here>      */
  };
  gchar expected_output[4 * sizeof (guint16)];

  guint32 calculated_pc;
  const GumArmInstruction * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = (fixture->rl.input_pc + 4 + 1896) & ~(4 - 1);
  *((guint32 *) (expected_output + 4)) = GUINT32_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 4);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_LDRPC_T2);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (addh_should_be_rewritten_if_pc_relative)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x447a),   /* add r2, pc       */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb401),   /* push {r0}        */
    GUINT16_TO_LE (0x4801),   /* ldr r0, [pc, #4] */
    GUINT16_TO_LE (0x4402),   /* add r2, r0       */
    GUINT16_TO_LE (0xbc01),   /* pop {r0}         */
    GUINT16_TO_LE (0xffff),   /* <calculated PC   */
    GUINT16_TO_LE (0xffff),   /*  goes here>      */
  };
  gchar expected_output[6 * sizeof (guint16)];

  guint32 calculated_pc;
  const GumArmInstruction * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_pc = fixture->rl.input_pc + 4;
  *((guint32 *) (expected_output + 8)) = GUINT32_TO_LE (calculated_pc);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_ADDH);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

/*
 * Branch instruction coverage based on DDI0487A_b_armv8_arm.pdf
 *
 * B imm (F7.1.18)
 * [ ] T1
 * [x] T2
 * [ ] T3
 * [x] T4
 *
 * BL, BLX imm (F7.1.25)
 * [x] T1
 * [x] T2
 */

typedef struct _BranchScenario BranchScenario;

struct _BranchScenario
{
  GumArmMnemonic mnemonic;
  guint16 input[2];
  gsize input_length;
  gsize instruction_length;
  guint16 expected_output[8];
  gsize expected_output_length;
  gsize pc_offset;
  gssize expected_pc_distance;
};

static void branch_scenario_execute (BranchScenario * bs,
    TestThumbRelocatorFixture * fixture);

RELOCATOR_TESTCASE (b_imm_t2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_T2,
    { 0xe004 }, 1, 2,           /* b pc + 8         */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 9
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (b_imm_t2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_T2,
    { 0xe7fc }, 1, 2,           /* b pc - 8         */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -7
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (b_imm_t4_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_T4,
    { 0xf001, 0xb91a }, 2, 4,   /* b pc + 0x1234    */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1235
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (b_imm_t4_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_B_IMM_T4,
    { 0xf7fe, 0xbee6 }, 2, 4,   /* b pc - 0x1234    */
    {
      0xb401,                   /* push {r0}        */
      0xb401,                   /* push {r0}        */
      0x4801,                   /* ldr r0, [pc, #4] */
      0x9001,                   /* str r0, [sp, #4] */
      0xbd01,                   /* pop {r0, pc}     */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1233
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (bl_imm_t1_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BL_IMM_T1,
    { 0xf001, 0xf91a }, 2, 4,   /* bl pc + 0x1234   */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1235
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (bl_imm_t1_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BL_IMM_T1,
    { 0xf7fe, 0xfee6 }, 2, 4,   /* bl pc - 0x1234   */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1233
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (blx_imm_t2_positive_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BLX_IMM_T2,
    { 0xf001, 0xe91a }, 2, 4,   /* blx pc + 0x1234  */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, 0x1234
  };
  branch_scenario_execute (&bs, fixture);
}

RELOCATOR_TESTCASE (blx_imm_t2_negative_should_be_rewritten)
{
  BranchScenario bs = {
    GUM_ARM_BLX_IMM_T2,
    { 0xf7fe, 0xeee6 }, 2, 4,   /* blx pc - 0x1234  */
    {
      0xb401,                   /* push {r0}        */
      0x4802,                   /* ldr r0, [pc, #8] */
      0x4686,                   /* mov lr, r0       */
      0xbc01,                   /* pop {r0}         */
      0x47f0,                   /* blx lr           */
      0x0000,                   /* <padding>        */
      0xffff,                   /* <calculated PC   */
      0xffff                    /*  goes here>      */
    }, 8,
    6, -0x1234
  };
  branch_scenario_execute (&bs, fixture);
}

static void
branch_scenario_execute (BranchScenario * bs,
                         TestThumbRelocatorFixture * fixture)
{
  gsize i;
  guint32 calculated_pc;
  const GumArmInstruction * insn = NULL;

  for (i = 0; i != bs->input_length; i++)
    bs->input[i] = GUINT16_TO_LE (bs->input[i]);
  for (i = 0; i != bs->expected_output_length; i++)
    bs->expected_output[i] = GUINT16_TO_LE (bs->expected_output[i]);

  SETUP_RELOCATOR_WITH (bs->input);

  calculated_pc = fixture->rl.input_pc + 4 + bs->expected_pc_distance;
  bs->expected_output[bs->pc_offset + 0] =
      GUINT16_TO_LE ((calculated_pc >> 0) & 0xffff);
  bs->expected_output[bs->pc_offset + 1] =
      GUINT16_TO_LE ((calculated_pc >> 16) & 0xffff);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn),
      ==, bs->instruction_length);
  g_assert_cmpint (insn->mnemonic, ==, bs->mnemonic);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, bs->expected_output,
      bs->expected_output_length * sizeof (guint16)), ==, 0);
}

RELOCATOR_TESTCASE (cbz_should_be_rewritten)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0xb1e8),     /* cbz r0, #imm     */
    GUINT16_TO_LE (0xbd01)      /* pop {r0, pc}     */
  };
  const guint16 expected_output_instructions[] = {
    GUINT16_TO_LE (0xb100),     /* cbz r0, #imm     */
  /* if_false: jump to next instruction */
    GUINT16_TO_LE (0xe004),     /* b pc + 8         */
  /* if_true: */
    GUINT16_TO_LE (0xb401),     /* push {r0}        */
    GUINT16_TO_LE (0xb401),     /* push {r0}        */
    GUINT16_TO_LE (0x4801),     /* ldr r0, [pc, #4] */
    GUINT16_TO_LE (0x9001),     /* str r0, [sp, #4] */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}     */
  /* next instruction */
    GUINT16_TO_LE (0xbd01),     /* pop {r0, pc}     */
    GUINT16_TO_LE (0xffff),
    GUINT16_TO_LE (0xffff)
  };
  guint32 calculated_target;
  gchar expected_output[10 * sizeof (guint16)];
  const GumArmInstruction * insn = NULL;

  SETUP_RELOCATOR_WITH (input);

  memcpy (expected_output, expected_output_instructions,
      sizeof (expected_output_instructions));
  calculated_target = (fixture->rl.input_pc + 4 + ((0xe8 >> 3) << 1)) | 1;
  *((guint32 *) (expected_output + 16)) = GUINT32_TO_LE (calculated_target);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, &insn), ==, 2);
  g_assert_cmpint (insn->mnemonic, ==, GUM_ARM_CBZ);
  gum_thumb_relocator_read_one (&fixture->rl, &insn);
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  g_assert (gum_thumb_relocator_write_one (&fixture->rl));
  gum_thumb_writer_flush (&fixture->tw);
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (eob_and_eoi_on_ret)
{
  const guint16 input[] = {
    GUINT16_TO_LE (0x4770)  /* bx lr */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_thumb_relocator_eob (&fixture->rl));
  g_assert (gum_thumb_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_thumb_relocator_read_one (&fixture->rl, NULL), ==, 0);
}
