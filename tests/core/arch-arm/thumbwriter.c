/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "thumbwriter-fixture.c"

TEST_LIST_BEGIN (thumbwriter)
  THUMBWRITER_TESTENTRY (cmp_reg_imm)
  THUMBWRITER_TESTENTRY (beq_label)
  THUMBWRITER_TESTENTRY (bne_label)
  THUMBWRITER_TESTENTRY (b_cond_label_wide)
  THUMBWRITER_TESTENTRY (cbz_reg_label)
  THUMBWRITER_TESTENTRY (cbnz_reg_label)

  THUMBWRITER_TESTENTRY (b_label_wide)
  THUMBWRITER_TESTENTRY (bx_reg)
  THUMBWRITER_TESTENTRY (bl_label)
  THUMBWRITER_TESTENTRY (blx_reg)

  THUMBWRITER_TESTENTRY (push_regs)
  THUMBWRITER_TESTENTRY (pop_regs)
  THUMBWRITER_TESTENTRY (ldr_u32)
#ifdef HAVE_ARM
  THUMBWRITER_TESTENTRY (ldr_in_large_block)
#endif
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

  THUMBWRITER_TESTENTRY (mrs_reg_reg)
  THUMBWRITER_TESTENTRY (msr_reg_reg)

  THUMBWRITER_TESTENTRY (nop)
TEST_LIST_END ()

#ifdef HAVE_ARM
static void gum_emit_ldr_in_large_block (gpointer mem, gpointer user_data);
#endif

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

THUMBWRITER_TESTCASE (b_cond_label_wide)
{
  const gchar * again_lbl = "again";

  gum_thumb_writer_put_label (&fixture->tw, again_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_nop (&fixture->tw);
  gum_thumb_writer_put_b_cond_label_wide (&fixture->tw, ARM_CC_NE, again_lbl);

  gum_thumb_writer_flush (&fixture->tw);

  /* again: */
  assert_output_n_equals (0, 0x46c0); /* nop */
  assert_output_n_equals (1, 0x46c0); /* nop */
  assert_output_n_equals (2, 0x46c0); /* nop */
  assert_output_n_equals (3, 0xf47f); /* bne.w again */
  assert_output_n_equals (4, 0xaffb);
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

THUMBWRITER_TESTCASE (b_label_wide)
{
  const gchar * next_lbl = "next";

  gum_thumb_writer_put_b_label_wide (&fixture->tw, next_lbl);
  gum_thumb_writer_put_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_nop (&fixture->tw);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xf000); /* b.w next */
  assert_output_n_equals (1, 0xb800);
  /* next: */
  assert_output_n_equals (2, 0x46c0); /* nop */
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

THUMBWRITER_TESTCASE (bl_label)
{
  const gchar * next_lbl = "next";

  gum_thumb_writer_put_push_regs (&fixture->tw, 1, ARM_REG_LR);
  gum_thumb_writer_put_bl_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_PC);
  gum_thumb_writer_put_label (&fixture->tw, next_lbl);
  gum_thumb_writer_put_mov_reg_u8 (&fixture->tw, ARM_REG_R2, 0);

  gum_thumb_writer_flush (&fixture->tw);

  assert_output_n_equals (0, 0xb500); /* push {lr} */
  assert_output_n_equals (1, 0xf000); /* bl next */
  assert_output_n_equals (2, 0xf801);
  assert_output_n_equals (3, 0xbd00); /* pop {pc} */
  /* next: */
  assert_output_n_equals (4, 0x2200); /* movs r2, 0 */
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

  gum_thumb_writer_put_push_regs (&fixture->tw, 2, ARM_REG_R8, ARM_REG_R9);
  assert_output_n_equals (3, 0xe92d);
  assert_output_n_equals (4, 0x0300);
}

THUMBWRITER_TESTCASE (pop_regs)
{
  gum_thumb_writer_put_pop_regs (&fixture->tw, 1, ARM_REG_R0);
  assert_output_n_equals (0, 0xbc01);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 9, ARM_REG_R0, ARM_REG_R1,
      ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);
  assert_output_n_equals (1, 0xbdff);

  gum_thumb_writer_put_pop_regs (&fixture->tw, 2, ARM_REG_R8, ARM_REG_R9);
  assert_output_n_equals (2, 0xe8bd);
  assert_output_n_equals (3, 0x0300);
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

#ifdef HAVE_ARM

THUMBWRITER_TESTCASE (ldr_in_large_block)
{
  const gsize code_size_in_pages = 1;
  gsize code_size;
  gpointer code;
  gint (* impl) (void);

  code_size = code_size_in_pages * gum_query_page_size ();
  code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  gum_memory_patch_code (GUM_ADDRESS (code), code_size,
      gum_emit_ldr_in_large_block, code);

  impl = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (code) | 1);
  g_assert_cmpint (impl (), ==, 0x1337);

  gum_free_pages (code);
}

static void
gum_emit_ldr_in_large_block (gpointer mem,
                             gpointer user_data)
{
  gpointer code = user_data;
  GumThumbWriter tw;
  guint i;

  gum_thumb_writer_init (&tw, mem);
  tw.pc = GUM_ADDRESS (code);

  gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 0x1337);
  for (i = 0; i != 511; i++)
    gum_thumb_writer_put_nop (&tw);
  gum_thumb_writer_put_bx_reg (&tw, ARM_REG_LR);

  gum_thumb_writer_clear (&tw);
}

#endif

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

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_R12, 16);
  assert_output_n_equals (4, 0xf8dc);
  assert_output_n_equals (5, 0x3010);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (6, 0x9800);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R5,
      ARM_REG_SP, 0);
  assert_output_n_equals (7, 0x9d00);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 12);
  assert_output_n_equals (8, 0x9803);

  gum_thumb_writer_put_ldr_reg_reg_offset (&fixture->tw, ARM_REG_R12,
      ARM_REG_SP, 12);
  assert_output_n_equals (9, 0xf8dd);
  assert_output_n_equals (10, 0xc00c);
}

THUMBWRITER_TESTCASE (ldr_reg_reg)
{
  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, ARM_REG_R0, ARM_REG_R0);
  assert_output_n_equals (0, 0x6800);

  gum_thumb_writer_put_ldr_reg_reg (&fixture->tw, ARM_REG_R12, ARM_REG_R12);
  assert_output_n_equals (1, 0xf8dc);
  assert_output_n_equals (2, 0xc000);
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

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R4,
      ARM_REG_R11, 28);
  assert_output_n_equals (4, 0xf8cb);
  assert_output_n_equals (5, 0x401c);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 0);
  assert_output_n_equals (6, 0x9000);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R3,
      ARM_REG_SP, 0);
  assert_output_n_equals (7, 0x9300);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R0,
      ARM_REG_SP, 24);
  assert_output_n_equals (8, 0x9006);

  gum_thumb_writer_put_str_reg_reg_offset (&fixture->tw, ARM_REG_R12,
      ARM_REG_SP, 24);
  assert_output_n_equals (9, 0xf8cd);
  assert_output_n_equals (10, 0xc018);
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
  assert_output_n_equals (0, 0x4408);

  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R12, ARM_REG_R1);
  assert_output_n_equals (1, 0x448c);

  gum_thumb_writer_put_add_reg_reg (&fixture->tw, ARM_REG_R3, ARM_REG_R12);
  assert_output_n_equals (2, 0x4463);
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

THUMBWRITER_TESTCASE (mrs_reg_reg)
{
  gum_thumb_writer_put_mrs_reg_reg (&fixture->tw, ARM_REG_R1,
      ARM_SYSREG_APSR_NZCVQ);
  assert_output_n_equals (0, 0xf3ef);
  assert_output_n_equals (1, 0x8100);

  gum_thumb_writer_put_mrs_reg_reg (&fixture->tw, ARM_REG_R7,
      ARM_SYSREG_APSR_NZCVQ);
  assert_output_n_equals (2, 0xf3ef);
  assert_output_n_equals (3, 0x8700);
}

THUMBWRITER_TESTCASE (msr_reg_reg)
{
  gum_thumb_writer_put_msr_reg_reg (&fixture->tw, ARM_SYSREG_APSR_NZCVQ,
      ARM_REG_R1);
  assert_output_n_equals (0, 0xf381);
  assert_output_n_equals (1, 0x8800);

  gum_thumb_writer_put_msr_reg_reg (&fixture->tw, ARM_SYSREG_APSR_NZCVQ,
      ARM_REG_R7);
  assert_output_n_equals (2, 0xf387);
  assert_output_n_equals (3, 0x8800);
}

THUMBWRITER_TESTCASE (nop)
{
  gum_thumb_writer_put_nop (&fixture->tw);
  assert_output_equals (0x46c0);
}
