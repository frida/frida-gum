/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "codewriter-fixture.c"

TEST_LIST_BEGIN (codewriter)
  CODEWRITER_TESTENTRY (jump_label)
  CODEWRITER_TESTENTRY (call_label)
  CODEWRITER_TESTENTRY (flush_on_free)
  CODEWRITER_TESTENTRY (mov_ecx_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_rcx_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_r10d_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_r10_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_ecx_r11_offset_ptr)
TEST_LIST_END ()

CODEWRITER_TESTCASE (jump_label)
{
  const guint8 expected_code[] = {
  /* start: */
    0x81, 0xf9, 0x39, 0x05, 0x00, 0x00, /* cmp ecx, 1337        */
    0x2e, 0x74, 0x05,                   /* hnt je handle_error  */
    0x2e, 0x7e, 0x02,                   /* hnt jle handle_error */
    0xeb, 0x01,                         /* jmp beach            */
  /* handle_error: */
    0xcc,                               /* int 3                */
  /* beach: */
    0x90,                               /* nop                  */
    0xeb, 0xee                          /* jmp start            */
  };
  const gchar * start_lbl = "start";
  const gchar * handle_error_lbl = "handle_error";
  const gchar * beach_lbl = "beach";

  gum_code_writer_put_label (&fixture->cw, start_lbl);
  gum_code_writer_put_cmp_reg_i32 (&fixture->cw, GUM_REG_ECX, 1337);
  gum_code_writer_put_jz_label (&fixture->cw, handle_error_lbl, GUM_UNLIKELY);
  gum_code_writer_put_jle_label (&fixture->cw, handle_error_lbl, GUM_UNLIKELY);
  gum_code_writer_put_jmp_short_label (&fixture->cw, beach_lbl);

  gum_code_writer_put_label (&fixture->cw, handle_error_lbl);
  gum_code_writer_put_int3 (&fixture->cw);

  gum_code_writer_put_label (&fixture->cw, beach_lbl);
  gum_code_writer_put_nop (&fixture->cw);
  gum_code_writer_put_jmp_short_label (&fixture->cw, start_lbl);

  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (call_label)
{
  const guint8 expected_code[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call func */
    0xc3,                         /* retn      */
  /* func: */
    0xc3                          /* retn      */
  };
  const gchar * func_lbl = "func";

  gum_code_writer_put_call_near_label (&fixture->cw, func_lbl);
  gum_code_writer_put_ret (&fixture->cw);

  gum_code_writer_put_label (&fixture->cw, func_lbl);
  gum_code_writer_put_ret (&fixture->cw);

  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (flush_on_free)
{
  const guint8 expected_code[] = {
    0xe8, 0x00, 0x00, 0x00, 0x00, /* call func */
    0xc3                          /* retn      */
  };
  GumCodeWriter * cw = &fixture->cw;
  const gchar * func_lbl = "func";

  gum_code_writer_put_call_near_label (cw, func_lbl);
  gum_code_writer_put_label (cw, func_lbl);
  gum_code_writer_put_ret (cw);

  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (mov_ecx_rsi_offset_ptr)
{
  const guint8 expected_code[] = { 0x8b, 0x8e, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_mov_reg_reg_offset_ptr (&fixture->cw, GUM_REG_ECX,
      GUM_REG_RSI, 0x1337);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (mov_rcx_rsi_offset_ptr)
{
  const guint8 expected_code[] = { 0x48, 0x8b, 0x8e, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_mov_reg_reg_offset_ptr (&fixture->cw, GUM_REG_RCX,
      GUM_REG_RSI, 0x1337);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (mov_r10d_rsi_offset_ptr)
{
  const guint8 expected_code[] = { 0x44, 0x8b, 0x96, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_mov_reg_reg_offset_ptr (&fixture->cw, GUM_REG_R10D,
      GUM_REG_RSI, 0x1337);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (mov_r10_rsi_offset_ptr)
{
  const guint8 expected_code[] = { 0x4c, 0x8b, 0x96, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_mov_reg_reg_offset_ptr (&fixture->cw, GUM_REG_R10,
      GUM_REG_RSI, 0x1337);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (mov_ecx_r11_offset_ptr)
{
  const guint8 expected_code[] = { 0x41, 0x8b, 0x8b, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_mov_reg_reg_offset_ptr (&fixture->cw, GUM_REG_ECX,
      GUM_REG_R11, 0x1337);
  assert_output_equals (expected_code);
}
