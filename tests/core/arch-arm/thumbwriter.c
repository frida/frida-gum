/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "thumbwriter-fixture.c"

TEST_LIST_BEGIN (thumbwriter)
  THUMBWRITER_TESTENTRY (cmp_reg_imm)
  THUMBWRITER_TESTENTRY (beq_label)
  THUMBWRITER_TESTENTRY (bne_label)
  THUMBWRITER_TESTENTRY (cbz_reg_label)
  THUMBWRITER_TESTENTRY (cbnz_reg_label)

  THUMBWRITER_TESTENTRY (bx_reg)
  THUMBWRITER_TESTENTRY (blx_reg)

  THUMBWRITER_TESTENTRY (push_regs)
  THUMBWRITER_TESTENTRY (pop_regs)
  THUMBWRITER_TESTENTRY (ldr_u32)
  THUMBWRITER_TESTENTRY (ldr_reg_reg_offset)
  THUMBWRITER_TESTENTRY (ldr_reg_reg)
  THUMBWRITER_TESTENTRY (str_reg_reg_offset)
  THUMBWRITER_TESTENTRY (str_reg_reg)
  THUMBWRITER_TESTENTRY (mov_reg_reg)
  THUMBWRITER_TESTENTRY (mov_reg_u8)
  THUMBWRITER_TESTENTRY (add_reg_imm)
  THUMBWRITER_TESTENTRY (add_reg_reg_reg)
  THUMBWRITER_TESTENTRY (add_reg_reg)
  THUMBWRITER_TESTENTRY (add_reg_reg_imm)
  THUMBWRITER_TESTENTRY (sub_reg_imm)
  THUMBWRITER_TESTENTRY (sub_reg_reg_reg)
  THUMBWRITER_TESTENTRY (sub_reg_reg_imm)

  THUMBWRITER_TESTENTRY (nop)
TEST_LIST_END ()

THUMBWRITER_TESTCASE (cmp_reg_imm)
{
  gum_thumb_writer_put_cmp_reg_imm (&fixture->tw, ARM_REG_R7, 7);
  assert_output_n_equals (0, 0x2f07); /* cmp r7, 7 */
}

THUMBWRITER_TESTCASE (beq_label)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_beq_label (&fixture->tw, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0x46c0); /* nop */
  assert_output_n_equals (1, 0x46c0); /* nop */
  assert_output_n_equals (2, 0x46c0); /* nop */
  assert_output_n_equals (3, 0xd0fb); /* beq again */
}

THUMBWRITER_TESTCASE (bne_label)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_bne_label (&fixture->tw, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0x46c0); /* nop */
  assert_output_n_equals (1, 0x46c0); /* nop */
  assert_output_n_equals (2, 0x46c0); /* nop */
  assert_output_n_equals (3, 0xd1fb); /* bne again */
}

THUMBWRITER_TESTCASE (cbz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbz_reg_label (&fixture->tw, ARM_REG_R7, beach_lbl);
  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R1);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);

  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_PC);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb11f); /* cbz r7, beach */
  assert_output_n_equals (1, 0x4788); /* blx r1 */
  assert_output_n_equals (2, 0x46c0); /* nop */
  assert_output_n_equals (3, 0x46c0); /* nop */
  assert_output_n_equals (4, 0x46c0); /* nop */
  /* beach: */
  assert_output_n_equals (5, 0xbd00); /* pop {pc} */
}

THUMBWRITER_TESTCASE (cbnz_reg_label)
{
  const gchar * beach_lbl = "beach";

  gum_thumb_writer_put_cbnz_reg_label (&fixture->tw, ARM_REG_R0, beach_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_label (&fixture->tw, beach_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb910); /* cbnz r0, beach */
  assert_output_n_equals (1, 0x46c0); /* nop */
  assert_output_n_equals (2, 0x46c0); /* nop */
  assert_output_n_equals (3, 0x46c0); /* nop */
  /* beach: */
}

THUMBWRITER_TESTCASE (bx_reg)
{
  gum_thumb_writer_put_bx_reg (&fixture->tw, ARM_REG_R0);
  assert_output_n_equals (0, 0x4700);

  gum_thumb_writer_put_bx_reg (&fixture->tw, ARM_REG_R7);
  assert_output_n_equals (1, 0x4738);
}

THUMBWRITER_TESTCASE (blx_reg)
{
  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R0);
  assert_output_n_equals (0, 0x4780);

  gum_thumb_writer_put_blx_reg (&fixture->tw, ARM_REG_R3);
  assert_output_n_equals (1, 0x4798);
}

THUMBWRITER_TESTCASE (push_regs)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_R0);
  assert_output_n_equals (0, 0xb401);

  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_R7);
  assert_output_n_equals (1, 0xb480);

  gum_thumb_writer_put_push_regs (&fixture->tw, 9, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);
  assert_output_n_equals (2, 0xb5ff);
}

THUMBWRITER_TESTCASE (pop_regs)
{
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_R0);
  assert_output_n_equals (0, 0xbc01);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 9, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);
  assert_output_n_equals (1, 0xbdff);
}

THUMBWRITER_TESTCASE (ldr_u32)
{
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R0, 0x1337);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R1, 0x1227);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, ARM_REG_R2, 0x1337);
  gum_thumb_writer_flush (&fixture->tw);
  assert_output_n_equals (0, 0x4801);
  assert_output_n_equals (1, 0x4902);
  assert_output_n_equals (2, 0x4a00);
  g_assert_cmphex (GUINT32_FROM_LE (((guint32 *) fixture->output)[2]),
      ==, 0x1337);
  g_assert_cmphex (GUINT32_FROM_LE (((guint32 *) fixture->output)[3]),
      ==, 0x1227);
}

THUMBWRITER_TESTCASE (ldr_reg_reg_offset)
{
  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 0);
  assert_output_n_equals (0, 0x6800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_R0, 0);
  assert_output_n_equals (1, 0x6803);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R3, 0);
  assert_output_n_equals (2, 0x6818);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 12);
  assert_output_n_equals (3, 0x68c0);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (4, 0x9800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R5,
      ARM_REG_SP, 0);
  assert_output_n_equals (5, 0x9d00);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 12);
  assert_output_n_equals (6, 0x9803);
}

THUMBWRITER_TESTCASE (ldr_reg_reg)
{
  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R0);
  assert_output_equals (0x6800);
}

THUMBWRITER_TESTCASE (str_reg_reg_offset)
{
  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 0);
  assert_output_n_equals (0, 0x6000);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R7,
      ARM_REG_R0, 0);
  assert_output_n_equals (1, 0x6007);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R7, 0);
  assert_output_n_equals (2, 0x6038);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_R0, 24);
  assert_output_n_equals (3, 0x6180);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (4, 0x9000);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_SP, 0);
  assert_output_n_equals (5, 0x9300);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 24);
  assert_output_n_equals (6, 0x9006);
}

THUMBWRITER_TESTCASE (str_reg_reg)
{
  gum_thumb_writer_put_str_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R0);
  assert_output_equals (0x6000);
}

THUMBWRITER_TESTCASE (mov_reg_reg)
{
  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1);
  assert_output_n_equals (0, 0x1c08);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7);
  assert_output_n_equals (1, 0x1c38);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R0);
  assert_output_n_equals (2, 0x1c07);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_SP);
  assert_output_n_equals (3, 0x4668);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R1, ARM_REG_SP);
  assert_output_n_equals (4, 0x4669);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_LR);
  assert_output_n_equals (5, 0x4670);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_LR, ARM_REG_R0);
  assert_output_n_equals (6, 0x4686);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_LR, ARM_REG_SP);
  assert_output_n_equals (7, 0x46ee);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, ARM_REG_PC, ARM_REG_LR);
  assert_output_n_equals (8, 0x46f7);
}

THUMBWRITER_TESTCASE (mov_reg_u8)
{
  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R0, 7);
  assert_output_n_equals (0, 0x2007);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R0, 255);
  assert_output_n_equals (1, 0x20ff);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R2, 5);
  assert_output_n_equals (2, 0x2205);
}

THUMBWRITER_TESTCASE (add_reg_imm)
{
  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, 255);
  assert_output_n_equals (0, 0x30ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R3, 255);
  assert_output_n_equals (1, 0x33ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, 42);
  assert_output_n_equals (2, 0x302a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_R0, -42);
  assert_output_n_equals (3, 0x382a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_SP, 12);
  assert_output_n_equals (4, 0xb003);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, ARM_REG_SP, -12);
  assert_output_n_equals (5, 0xb083);
}

THUMBWRITER_TESTCASE (add_reg_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (0, 0x1888);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (1, 0x188f);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7,
      ARM_REG_R2);
  assert_output_n_equals (2, 0x18b8);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R7);
  assert_output_n_equals (3, 0x19c8);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, ARM_REG_R9, ARM_REG_R9,
      ARM_REG_R0);
  assert_output_n_equals (4, 0x4481);
}

THUMBWRITER_TESTCASE (add_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1);
  assert_output_equals (0x4408);
}

THUMBWRITER_TESTCASE (add_reg_reg_imm)
{
  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_SP,
      36);
  assert_output_n_equals (0, 0xa909);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R7, ARM_REG_SP,
      36);
  assert_output_n_equals (1, 0xaf09);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_PC,
      36);
  assert_output_n_equals (2, 0xa109);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_SP,
      12);
  assert_output_n_equals (3, 0xa903);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      5);
  assert_output_n_equals (4, 0x1d79);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R5, ARM_REG_R7,
      5);
  assert_output_n_equals (5, 0x1d7d);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R3,
      5);
  assert_output_n_equals (6, 0x1d59);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      3);
  assert_output_n_equals (7, 0x1cf9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      -3);
  assert_output_n_equals (8, 0x1ef9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, ARM_REG_R0, ARM_REG_R0,
      255);
  assert_output_n_equals (9, 0x30ff);
}

THUMBWRITER_TESTCASE (sub_reg_imm)
{
  gum_thumb_writer_put_sub_reg_imm (&fixture->tw, ARM_REG_R0, 42);
  assert_output_equals (0x382a);
}

THUMBWRITER_TESTCASE (sub_reg_reg_reg)
{
  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (0, 0x1a88);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R7, ARM_REG_R1,
      ARM_REG_R2);
  assert_output_n_equals (1, 0x1a8f);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R7,
      ARM_REG_R2);
  assert_output_n_equals (2, 0x1ab8);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R7);
  assert_output_n_equals (3, 0x1bc8);
}

THUMBWRITER_TESTCASE (sub_reg_reg_imm)
{
  gum_thumb_writer_put_sub_reg_reg_imm (&fixture->tw, ARM_REG_R1, ARM_REG_R7,
      5);
  assert_output_equals (0x1f79);
}

THUMBWRITER_TESTCASE (nop)
{
  gum_thumb_writer_put_nop (&fixture->tw);
  assert_output_equals (0x46c0);
}
