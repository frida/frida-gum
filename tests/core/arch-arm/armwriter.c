/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "armwriter-fixture.c"

TEST_LIST_BEGIN (armwriter)
  ARMWRITER_TESTENTRY (ldr_u32)
  ARMWRITER_TESTENTRY (ldr_pc_u32)

  ARMWRITER_TESTENTRY (nop)
TEST_LIST_END ()

ARMWRITER_TESTCASE (ldr_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R0, 0x1337);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R1, 0x1227);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R2, 0x1337);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe59f0004);
  assert_output_n_equals (1, 0xe59f1004);
  assert_output_n_equals (2, 0xe51f2004);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[3 + 0]), ==, 0x1337);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[3 + 1]), ==, 0x1227);
}

ARMWRITER_TESTCASE (ldr_pc_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_PC, 0xdeadbeef);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe51ff004);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[1 + 0]), ==, 0xdeadbeef);
}

ARMWRITER_TESTCASE (nop)
{
  gum_arm_writer_put_nop (&fixture->aw);
  assert_output_equals (0xe1a00000); /* mov r0, r0 */
}
