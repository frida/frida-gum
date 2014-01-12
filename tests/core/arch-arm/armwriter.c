/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "armwriter-fixture.c"

TEST_LIST_BEGIN (armwriter)
  ARMWRITER_TESTENTRY (ldr_u32)
  ARMWRITER_TESTENTRY (ldr_pc_u32)

  ARMWRITER_TESTENTRY (nop)
TEST_LIST_END ()

ARMWRITER_TESTCASE (ldr_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, GUM_AREG_R0, 0x1337);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, GUM_AREG_R1, 0x1227);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, GUM_AREG_R2, 0x1337);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe59f0004);
  assert_output_n_equals (1, 0xe59f1004);
  assert_output_n_equals (2, 0xe51f2004);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[3 + 0]), ==, 0x1337);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[3 + 1]), ==, 0x1227);
}

ARMWRITER_TESTCASE (ldr_pc_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, GUM_AREG_PC, 0xdeadbeef);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe51ff004);
  g_assert_cmphex (GUINT32_FROM_LE (fixture->output[1 + 0]), ==, 0xdeadbeef);
}

ARMWRITER_TESTCASE (nop)
{
  gum_arm_writer_put_nop (&fixture->aw);
  assert_output_equals (0xe1a00000); /* mov r0, r0 */
}
