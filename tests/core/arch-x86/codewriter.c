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

  CODEWRITER_TESTENTRY (jmp_rcx)
  CODEWRITER_TESTENTRY (jmp_r8)
  CODEWRITER_TESTENTRY (jmp_rsp_ptr)
  CODEWRITER_TESTENTRY (jmp_r8_ptr)

  CODEWRITER_TESTENTRY (add_eax_ecx)
  CODEWRITER_TESTENTRY (add_rax_rcx)
  CODEWRITER_TESTENTRY (add_r8_rcx)

  CODEWRITER_TESTENTRY (lock_xadd_rcx_ptr_eax)
  CODEWRITER_TESTENTRY (lock_xadd_rcx_ptr_rax)
  CODEWRITER_TESTENTRY (lock_xadd_r15_ptr_eax)
  CODEWRITER_TESTENTRY (lock_inc_dec_imm32_ptr)

  CODEWRITER_TESTENTRY (and_eax_u32)
  CODEWRITER_TESTENTRY (and_rax_u32)
  CODEWRITER_TESTENTRY (and_r13_u32)
  CODEWRITER_TESTENTRY (shl_eax_u8)
  CODEWRITER_TESTENTRY (shl_rax_u8)

  CODEWRITER_TESTENTRY (mov_ecx_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_rcx_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_r10d_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_r10_rsi_offset_ptr)
  CODEWRITER_TESTENTRY (mov_ecx_r11_offset_ptr)

  CODEWRITER_TESTENTRY (test_eax_ecx)
  CODEWRITER_TESTENTRY (test_rax_rcx)
  CODEWRITER_TESTENTRY (test_rax_r9)
  CODEWRITER_TESTENTRY (cmp_eax_i32)
  CODEWRITER_TESTENTRY (cmp_r9_i32)
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

CODEWRITER_TESTCASE (jmp_rcx)
{
  const guint8 expected_code[] = { 0xff, 0xe1 };
  gum_code_writer_put_jmp_reg (&fixture->cw, GUM_REG_RCX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (jmp_r8)
{
  const guint8 expected_code[] = { 0x41, 0xff, 0xe0 };
  gum_code_writer_put_jmp_reg (&fixture->cw, GUM_REG_R8);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (jmp_rsp_ptr)
{
  const guint8 expected_code[] = { 0xff, 0x24, 0x24 };
  gum_code_writer_put_jmp_reg_ptr (&fixture->cw, GUM_REG_RSP);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (jmp_r8_ptr)
{
  const guint8 expected_code[] = { 0x41, 0xff, 0x20 };
  gum_code_writer_put_jmp_reg_ptr (&fixture->cw, GUM_REG_R8);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (add_eax_ecx)
{
  const guint8 expected_code[] = { 0x01, 0xc8 };
  gum_code_writer_put_add_reg_reg (&fixture->cw, GUM_REG_EAX, GUM_REG_ECX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (add_rax_rcx)
{
  const guint8 expected_code[] = { 0x48, 0x01, 0xc8 };
  gum_code_writer_put_add_reg_reg (&fixture->cw, GUM_REG_RAX, GUM_REG_RCX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (add_r8_rcx)
{
  const guint8 expected_code[] = { 0x49, 0x01, 0xc8 };
  gum_code_writer_put_add_reg_reg (&fixture->cw, GUM_REG_R8, GUM_REG_RCX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (lock_xadd_rcx_ptr_eax)
{
  const guint8 expected_code[] = { 0xf0, 0x0f, 0xc1, 0x01 };
  gum_code_writer_put_lock_xadd_reg_ptr_reg (&fixture->cw, GUM_REG_RCX,
      GUM_REG_EAX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (lock_xadd_rcx_ptr_rax)
{
  const guint8 expected_code[] = { 0xf0, 0x48, 0x0f, 0xc1, 0x01 };
  gum_code_writer_put_lock_xadd_reg_ptr_reg (&fixture->cw, GUM_REG_RCX,
      GUM_REG_RAX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (lock_xadd_r15_ptr_eax)
{
  const guint8 expected_code[] = { 0xf0, 0x41, 0x0f, 0xc1, 0x07 };
  gum_code_writer_put_lock_xadd_reg_ptr_reg (&fixture->cw, GUM_REG_R15,
      GUM_REG_EAX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (lock_inc_dec_imm32_ptr)
{
  gpointer target;
  guint8 expected_code[] = { 0xf0, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00 };

  target = fixture->output + 32;

#if GLIB_SIZEOF_VOID_P == 4
  gum_code_writer_set_target_cpu (&fixture->cw, GUM_CPU_IA32);
  *((gpointer *) (expected_code + 3)) = target;
#else
  gum_code_writer_set_target_cpu (&fixture->cw, GUM_CPU_AMD64);
  *((gint32 *) (expected_code + 3)) = 32 - sizeof (expected_code);
#endif

  gum_code_writer_put_lock_inc_imm32_ptr (&fixture->cw, target);
  assert_output_equals (expected_code);

  gum_code_writer_reset (&fixture->cw, fixture->output);

  expected_code[2] = 0x0d;
  gum_code_writer_put_lock_dec_imm32_ptr (&fixture->cw, target);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (and_eax_u32)
{
  const guint8 expected_code[] = { 0x25, 0xff, 0xff, 0xff, 0xff };
  gum_code_writer_put_and_reg_u32 (&fixture->cw, GUM_REG_EAX, 0xffffffff);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (and_rax_u32)
{
  const guint8 expected_code[] = { 0x48, 0x25, 0xff, 0xff, 0xff, 0xff };
  gum_code_writer_put_and_reg_u32 (&fixture->cw, GUM_REG_RAX, 0xffffffff);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (and_r13_u32)
{
  const guint8 expected_code[] = { 0x49, 0x81, 0xe5, 0xff, 0xff, 0xff, 0xff };
  gum_code_writer_put_and_reg_u32 (&fixture->cw, GUM_REG_R13, 0xffffffff);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (shl_eax_u8)
{
  const guint8 expected_code[] = { 0xc1, 0xe0, 0x07 };
  gum_code_writer_put_shl_reg_u8 (&fixture->cw, GUM_REG_EAX, 7);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (shl_rax_u8)
{
  const guint8 expected_code[] = { 0x48, 0xc1, 0xe0, 0x07 };
  gum_code_writer_put_shl_reg_u8 (&fixture->cw, GUM_REG_RAX, 7);
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

CODEWRITER_TESTCASE (test_eax_ecx)
{
  const guint8 expected_code[] = { 0x85, 0xc8 };
  gum_code_writer_put_test_reg_reg (&fixture->cw, GUM_REG_EAX, GUM_REG_ECX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (test_rax_rcx)
{
  const guint8 expected_code[] = { 0x48, 0x85, 0xc8 };
  gum_code_writer_put_test_reg_reg (&fixture->cw, GUM_REG_RAX, GUM_REG_RCX);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (test_rax_r9)
{
  const guint8 expected_code[] = { 0x4c, 0x85, 0xc8 };
  gum_code_writer_put_test_reg_reg (&fixture->cw, GUM_REG_RAX, GUM_REG_R9);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (cmp_eax_i32)
{
  const guint8 expected_code[] = { 0x3d, 0xff, 0xff, 0xff, 0xff };
  gum_code_writer_put_cmp_reg_i32 (&fixture->cw, GUM_REG_EAX, -1);
  assert_output_equals (expected_code);
}

CODEWRITER_TESTCASE (cmp_r9_i32)
{
  const guint8 expected_code[] = { 0x49, 0x81, 0xf9, 0x37, 0x13, 0x00, 0x00 };
  gum_code_writer_put_cmp_reg_i32 (&fixture->cw, GUM_REG_R9, 0x1337);
  assert_output_equals (expected_code);
}
