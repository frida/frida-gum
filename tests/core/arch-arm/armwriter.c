/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "armwriter-fixture.c"

TESTLIST_BEGIN (armwriter)
  TESTENTRY (ldr_u32)
  TESTENTRY (ldr_pc_u32)
#ifdef HAVE_ARM
  TESTENTRY (ldr_in_large_block)
#endif

  TESTENTRY (nop)
TESTLIST_END ()

#ifdef HAVE_ARM
static void gum_emit_ldr_in_large_block (gpointer mem, gpointer user_data);
#endif

TESTCASE (ldr_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R0, 0x1337);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R1, 0x1227);
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_R2, 0x1337);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe59f0004);
  assert_output_n_equals (1, 0xe59f1004);
  assert_output_n_equals (2, 0xe51f2004);
  g_assert_cmphex (fixture->output[3 + 0], ==, 0x1337);
  g_assert_cmphex (fixture->output[3 + 1], ==, 0x1227);
}

TESTCASE (ldr_pc_u32)
{
  gum_arm_writer_put_ldr_reg_u32 (&fixture->aw, ARM_REG_PC, 0xdeadbeef);
  gum_arm_writer_flush (&fixture->aw);
  assert_output_n_equals (0, 0xe51ff004);
  g_assert_cmphex (fixture->output[1 + 0], ==, 0xdeadbeef);
}

#ifdef HAVE_ARM

TESTCASE (ldr_in_large_block)
{
  const gsize code_size_in_pages = 2;
  gsize code_size;
  gpointer code;
  gint (* impl) (void);

  code_size = code_size_in_pages * gum_query_page_size ();
  code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  gum_memory_patch_code (code, code_size, gum_emit_ldr_in_large_block, code);

  impl = code;
  g_assert_cmpint (impl (), ==, 0x1337);

  gum_free_pages (code);
}

static void
gum_emit_ldr_in_large_block (gpointer mem,
                             gpointer user_data)
{
  gpointer code = user_data;
  GumArmWriter aw;
  guint i;

  gum_arm_writer_init (&aw, mem);
  aw.pc = GUM_ADDRESS (code);

  gum_arm_writer_put_ldr_reg_u32 (&aw, ARM_REG_R0, 0x1337);
  for (i = 0; i != 1024; i++)
    gum_arm_writer_put_nop (&aw);
  gum_arm_writer_put_bx_reg (&aw, ARM_REG_LR);

  gum_arm_writer_clear (&aw);
}

#endif

TESTCASE (nop)
{
  gum_arm_writer_put_nop (&fixture->aw);
  assert_output_equals (0xe1a00000); /* mov r0, r0 */
}
