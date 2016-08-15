/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64writer-fixture.c"

TEST_LIST_BEGIN (arm64writer)
  TESTENTRY (cbz_reg_label)

  TESTENTRY (b_imm)
  TESTENTRY (bl_imm)
  TESTENTRY (br_reg)
  TESTENTRY (blr_reg)
  TESTENTRY (ret)

  TESTENTRY (push_reg_reg)
  TESTENTRY (pop_reg_reg)
  TESTENTRY (ldr_x_address)
  TESTENTRY (ldr_d_address)
  TESTENTRY (ldr_integer_reg_reg_imm)
  TESTENTRY (ldr_fp_reg_reg_imm)
  TESTENTRY (str_integer_reg_reg_imm)
  TESTENTRY (str_fp_reg_reg_imm)
  TESTENTRY (mov_reg_reg)
  TESTENTRY (add_reg_reg_imm)
  TESTENTRY (sub_reg_reg_imm)
TEST_LIST_END ()

TESTCASE (cbz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_arm64_writer_put_cbz_reg_label (&fixture->aw, ARM64_REG_W5, beach_lbl);
  gum_arm64_writer_put_cbz_reg_label (&fixture->aw, ARM64_REG_X7, beach_lbl);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 1);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 2);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 3);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 4);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 5);
  gum_arm64_writer_put_brk_imm (&fixture->aw, 6);

  gum_arm64_writer_put_label (&fixture->aw, beach_lbl);
  gum_arm64_writer_put_nop (&fixture->aw);

  gum_arm64_writer_flush (&fixture->aw);

  assert_output_n_equals (0, 0x34000105); /* cbz w5, beach */
  assert_output_n_equals (1, 0xb40000e7); /* cbz x7, beach */
  assert_output_n_equals (2, 0xd4200020); /* brk #1 */
  assert_output_n_equals (3, 0xd4200040); /* brk #2 */
  assert_output_n_equals (4, 0xd4200060); /* brk #3 */
  assert_output_n_equals (5, 0xd4200080); /* brk #4 */
  assert_output_n_equals (6, 0xd42000a0); /* brk #5 */
  assert_output_n_equals (7, 0xd42000c0); /* brk #6 */
  /* beach: */
  assert_output_n_equals (8, 0xd503201f); /* nop */
}

TESTCASE (b_imm)
{
  GumAddress from = 1024;
  g_assert (gum_arm64_writer_can_branch_imm (from, 1024 + 134217727));
  g_assert (!gum_arm64_writer_can_branch_imm (from, 1024 + 134217728));

  from = 1024 + 134217728;
  g_assert (gum_arm64_writer_can_branch_imm (from, 1024));
  g_assert (!gum_arm64_writer_can_branch_imm (from, 1023));

  fixture->aw.pc = 1024;
  gum_arm64_writer_put_b_imm (&fixture->aw, 2048);
  assert_output_n_equals (0, 0x14000100);
}

TESTCASE (bl_imm)
{
  fixture->aw.pc = 1024;
  gum_arm64_writer_put_bl_imm (&fixture->aw, 1028);
  assert_output_n_equals (0, 0x94000001);
}

TESTCASE (br_reg)
{
  gum_arm64_writer_put_br_reg (&fixture->aw, ARM64_REG_X3);
  assert_output_n_equals (0, 0xd61f0060);
}

TESTCASE (blr_reg)
{
  gum_arm64_writer_put_blr_reg (&fixture->aw, ARM64_REG_X5);
  assert_output_n_equals (0, 0xd63f00a0);
}

TESTCASE (ret)
{
  gum_arm64_writer_put_ret (&fixture->aw);
  assert_output_n_equals (0, 0xd65f03c0);
}

TESTCASE (push_reg_reg)
{
  gum_arm64_writer_put_push_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5);
  assert_output_n_equals (0, 0xa9bf17e3);

  gum_arm64_writer_put_push_reg_reg (&fixture->aw, ARM64_REG_W3, ARM64_REG_W5);
  assert_output_n_equals (1, 0x29bf17e3);
}

TESTCASE (pop_reg_reg)
{
  gum_arm64_writer_put_pop_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_X12);
  assert_output_n_equals (0, 0xa8c133e7);

  gum_arm64_writer_put_pop_reg_reg (&fixture->aw, ARM64_REG_W7, ARM64_REG_W12);
  assert_output_n_equals (1, 0x28c133e7);
}

TESTCASE (ldr_x_address)
{
  gum_arm64_writer_put_ldr_reg_address (&fixture->aw, ARM64_REG_X7,
      0x123456789abcdef0);
  gum_arm64_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0x58000027);
  g_assert_cmphex (
      GUINT64_FROM_LE (*((guint64 *) (((guint8 *) fixture->output) + 4))),
      ==, 0x123456789abcdef0);
}

TESTCASE (ldr_d_address)
{
  gum_arm64_writer_put_ldr_reg_address (&fixture->aw, ARM64_REG_D1,
      0x123456789abcdef0);
  gum_arm64_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0x5c000021);
  g_assert_cmphex (
      GUINT64_FROM_LE (*((guint64 *) (((guint8 *) fixture->output) + 4))),
      ==, 0x123456789abcdef0);
}

TESTCASE (ldr_integer_reg_reg_imm)
{
  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (0, 0xf94008a3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (1, 0xb94010a3);
}

TESTCASE (ldr_fp_reg_reg_imm)
{
  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_S3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (0, 0xbd4010e3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_D3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (1, 0xfd4008e3);

  gum_arm64_writer_put_ldr_reg_reg_offset (&fixture->aw, ARM64_REG_Q3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (2, 0x3dc004e3);
}

TESTCASE (str_integer_reg_reg_imm)
{
  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (0, 0xf90008a3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_W3,
      ARM64_REG_X5, 16);
  assert_output_n_equals (1, 0xb90010a3);
}

TESTCASE (str_fp_reg_reg_imm)
{
  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_S3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (0, 0xbd0010e3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_D3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (1, 0xfd0008e3);

  gum_arm64_writer_put_str_reg_reg_offset (&fixture->aw, ARM64_REG_Q3,
      ARM64_REG_X7, 16);
  assert_output_n_equals (2, 0x3d8004e3);
}

TESTCASE (mov_reg_reg)
{
  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_X3, ARM64_REG_X5);
  assert_output_n_equals (0, 0xaa0503e3);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_W3, ARM64_REG_W5);
  assert_output_n_equals (1, 0x2a0503e3);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_X7, ARM64_REG_SP);
  assert_output_n_equals (2, 0x910003e7);

  gum_arm64_writer_put_mov_reg_reg (&fixture->aw, ARM64_REG_SP, ARM64_REG_X12);
  assert_output_n_equals (3, 0x9100019f);
}

TESTCASE (add_reg_reg_imm)
{
  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 7);
  assert_output_n_equals (0, 0x91001ca3);

  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_X7,
      ARM64_REG_X12, 16);
  assert_output_n_equals (1, 0x91004187);

  gum_arm64_writer_put_add_reg_reg_imm (&fixture->aw, ARM64_REG_W7,
      ARM64_REG_W12, 16);
  assert_output_n_equals (2, 0x11004187);
}

TESTCASE (sub_reg_reg_imm)
{
  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_X3,
      ARM64_REG_X5, 7);
  assert_output_n_equals (0, 0xd1001ca3);

  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_X7,
      ARM64_REG_X12, 16);
  assert_output_n_equals (1, 0xd1004187);

  gum_arm64_writer_put_sub_reg_reg_imm (&fixture->aw, ARM64_REG_W7,
      ARM64_REG_W12, 16);
  assert_output_n_equals (2, 0x51004187);
}
