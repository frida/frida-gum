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
  THUMBWRITER_TESTENTRY (push_r0)
  THUMBWRITER_TESTENTRY (push_r7)
  THUMBWRITER_TESTENTRY (push_all_regs)
  THUMBWRITER_TESTENTRY (ldr_u32)
TEST_LIST_END ()

THUMBWRITER_TESTCASE (push_r0)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 1, GUM_TREG_R0);
  assert_output_equals (0xb401);
}

THUMBWRITER_TESTCASE (push_r7)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 1, GUM_TREG_R7);
  assert_output_equals (0xb480);
}

THUMBWRITER_TESTCASE (push_all_regs)
{
  gum_thumb_writer_put_push_regs (&fixture->tw, 9, GUM_TREG_R0, GUM_TREG_R1,
      GUM_TREG_R2, GUM_TREG_R3, GUM_TREG_R4, GUM_TREG_R5, GUM_TREG_R6,
      GUM_TREG_R7, GUM_TREG_LR);
  assert_output_equals (0xb5ff);
}

THUMBWRITER_TESTCASE (ldr_u32)
{
  gum_thumb_writer_put_ldr_u32 (&fixture->tw, GUM_TREG_R0, 0x1337);
  gum_thumb_writer_put_ldr_u32 (&fixture->tw, GUM_TREG_R1, 0x1227);
  gum_thumb_writer_put_ldr_u32 (&fixture->tw, GUM_TREG_R2, 0x1337);
  gum_thumb_writer_flush (&fixture->tw);
  assert_output_n_equals (0, 0x4801);
  assert_output_n_equals (1, 0x4902);
  assert_output_n_equals (2, 0x4a00);
  g_assert_cmphex (GUINT32_FROM_LE (*((guint32 *) (fixture->output + 3 + 1 +
      0))), ==, 0x1337);
  g_assert_cmphex (GUINT32_FROM_LE (*((guint32 *) (fixture->output + 3 + 1 +
      2))), ==, 0x1227);
}
