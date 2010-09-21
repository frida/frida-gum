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

#include "thumbwriter-fixture.c"

TEST_LIST_BEGIN (thumbwriter)
  THUMBWRITER_TESTENTRY (bx_reg)
  THUMBWRITER_TESTENTRY (blx_reg)

  THUMBWRITER_TESTENTRY (push_regs)
  THUMBWRITER_TESTENTRY (pop_regs)
  THUMBWRITER_TESTENTRY (ldr_u32)
  THUMBWRITER_TESTENTRY (ldr_reg_reg_offset)
  THUMBWRITER_TESTENTRY (ldr_reg_reg)
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

THUMBWRITER_TESTCASE (bx_reg)
{
  gum_thumb_writer_put_bx_reg (&fixture->tw, GUM_TREG_R0);
  assert_output_n_equals (0, 0x4700);

  gum_thumb_writer_put_bx_reg (&fixture->tw, GUM_TREG_R7);
  assert_output_n_equals (1, 0x4738);
}

THUMBWRITER_TESTCASE (blx_reg)
{
  gum_thumb_writer_put_blx_reg (&fixture->tw, GUM_TREG_R0);
  assert_output_n_equals (0, 0x4780);

  gum_thumb_writer_put_blx_reg (&fixture->tw, GUM_TREG_R3);
  assert_output_n_equals (1, 0x4798);
}

THUMBWRITER_TESTCASE (push_regs)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 1, GUM_TREG_R0);
  assert_output_n_equals (0, 0xb401);

  gum_thumb_writer_put_push_regs (&fixture->tw, 1, GUM_TREG_R7);
  assert_output_n_equals (1, 0xb480);

  gum_thumb_writer_put_push_regs (&fixture->tw, 9, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R2, GUM_TREG_R3, GUM_TREG_R4, GUM_TREG_R5, GUM_TREG_R6,
      GUM_TREG_R7, GUM_TREG_LR);
  assert_output_n_equals (2, 0xb5ff);
}

THUMBWRITER_TESTCASE (pop_regs)
{
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, GUM_TREG_R0);
  assert_output_n_equals (0, 0xbc01);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 9, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R2, GUM_TREG_R3, GUM_TREG_R4, GUM_TREG_R5, GUM_TREG_R6,
      GUM_TREG_R7, GUM_TREG_PC);
  assert_output_n_equals (1, 0xbdff);
}

THUMBWRITER_TESTCASE (ldr_u32)
{
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, GUM_TREG_R0, 0x1337);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, GUM_TREG_R1, 0x1227);
  gum_thumb_writer_put_ldr_reg_u32 (&fixture->tw, GUM_TREG_R2, 0x1337);
  gum_thumb_writer_flush (&fixture->tw);
  assert_output_n_equals (0, 0x4801);
  assert_output_n_equals (1, 0x4902);
  assert_output_n_equals (2, 0x4a00);
  g_assert_cmphex (GUINT32_FROM_LE (*((guint32 *) (fixture->output + 3 + 1 +
      0))), ==, 0x1337);
  g_assert_cmphex (GUINT32_FROM_LE (*((guint32 *) (fixture->output + 3 + 1 +
      2))), ==, 0x1227);
}

THUMBWRITER_TESTCASE (ldr_reg_reg_offset)
{
  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, GUM_TREG_R0,
      GUM_TREG_R0, 0);
  assert_output_n_equals (0, 0x6800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, GUM_TREG_R3,
      GUM_TREG_R0, 0);
  assert_output_n_equals (1, 0x6803);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, GUM_TREG_R0,
      GUM_TREG_R3, 0);
  assert_output_n_equals (2, 0x6818);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, GUM_TREG_R0,
      GUM_TREG_R0, 12);
  assert_output_n_equals (3, 0x68c0);
}

THUMBWRITER_TESTCASE (ldr_reg_reg)
{
  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R0);
  assert_output_equals (0x6800);
}

THUMBWRITER_TESTCASE (mov_reg_reg)
{
  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1);
  assert_output_n_equals (0, 0x1c08);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R7);
  assert_output_n_equals (1, 0x1c38);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R7, GUM_TREG_R0);
  assert_output_n_equals (2, 0x1c07);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_SP);
  assert_output_n_equals (3, 0x4668);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R1, GUM_TREG_SP);
  assert_output_n_equals (4, 0x4669);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_LR);
  assert_output_n_equals (5, 0x4670);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_LR, GUM_TREG_R0);
  assert_output_n_equals (6, 0x4686);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_LR, GUM_TREG_SP);
  assert_output_n_equals (7, 0x46ee);

  gum_thumb_writer_put_mov_reg_reg (&fixture->tw, GUM_TREG_PC, GUM_TREG_LR);
  assert_output_n_equals (8, 0x46f7);
}

THUMBWRITER_TESTCASE (mov_reg_u8)
{
  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, GUM_TREG_R0, 7);
  assert_output_n_equals (0, 0x2007);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, GUM_TREG_R0, 255);
  assert_output_n_equals (1, 0x20ff);

  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, GUM_TREG_R2, 5);
  assert_output_n_equals (2, 0x2205);
}

THUMBWRITER_TESTCASE (add_reg_imm)
{
  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_R0, 255);
  assert_output_n_equals (0, 0x30ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_R3, 255);
  assert_output_n_equals (1, 0x33ff);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_R0, 42);
  assert_output_n_equals (2, 0x302a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_R0, -42);
  assert_output_n_equals (3, 0x382a);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_SP, 12);
  assert_output_n_equals (4, 0xb003);

  gum_thumb_writer_put_add_reg_imm (&fixture->tw, GUM_TREG_SP, -12);
  assert_output_n_equals (5, 0xb083);
}

THUMBWRITER_TESTCASE (add_reg_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R2);
  assert_output_n_equals (0, 0x1888);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, GUM_TREG_R7, GUM_TREG_R1,
      GUM_TREG_R2);
  assert_output_n_equals (1, 0x188f);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R7,
      GUM_TREG_R2);
  assert_output_n_equals (2, 0x18b8);

  gum_thumb_writer_put_add_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R7);
  assert_output_n_equals (3, 0x19c8);
}

THUMBWRITER_TESTCASE (add_reg_reg)
{
  gum_thumb_writer_put_add_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1);
  assert_output_equals (0x1840);
}

THUMBWRITER_TESTCASE (add_reg_reg_imm)
{
  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_SP,
      36);
  assert_output_n_equals (0, 0xa909);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R7, GUM_TREG_SP,
      36);
  assert_output_n_equals (1, 0xaf09);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_PC,
      36);
  assert_output_n_equals (2, 0xa109);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_SP,
      12);
  assert_output_n_equals (3, 0xa903);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_R7,
      5);
  assert_output_n_equals (4, 0x1d79);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R5, GUM_TREG_R7,
      5);
  assert_output_n_equals (5, 0x1d7d);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_R3,
      5);
  assert_output_n_equals (6, 0x1d59);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_R7,
      3);
  assert_output_n_equals (7, 0x1cf9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_R7,
      -3);
  assert_output_n_equals (8, 0x1ef9);

  gum_thumb_writer_put_add_reg_reg_imm (&fixture->tw, GUM_TREG_R0, GUM_TREG_R0,
      255);
  assert_output_n_equals (9, 0x30ff);
}

THUMBWRITER_TESTCASE (sub_reg_imm)
{
  gum_thumb_writer_put_sub_reg_imm (&fixture->tw, GUM_TREG_R0, 42);
  assert_output_equals (0x382a);
}

THUMBWRITER_TESTCASE (sub_reg_reg_reg)
{
  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R2);
  assert_output_n_equals (0, 0x1a88);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, GUM_TREG_R7, GUM_TREG_R1,
      GUM_TREG_R2);
  assert_output_n_equals (1, 0x1a8f);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R7,
      GUM_TREG_R2);
  assert_output_n_equals (2, 0x1ab8);

  gum_thumb_writer_put_sub_reg_reg_reg (&fixture->tw, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R7);
  assert_output_n_equals (3, 0x1bc8);
}

THUMBWRITER_TESTCASE (sub_reg_reg_imm)
{
  gum_thumb_writer_put_sub_reg_reg_imm (&fixture->tw, GUM_TREG_R1, GUM_TREG_R7,
      5);
  assert_output_equals (0x1f79);
}

THUMBWRITER_TESTCASE (nop)
{
  gum_thumb_writer_put_nop (&fixture->tw);
  assert_output_equals (0x46c0);
}
