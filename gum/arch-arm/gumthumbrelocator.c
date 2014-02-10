/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumthumbrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const GumArmInstruction * insn;
  const guint16 * raw_insn;
  const guint8 * start;
  const guint8 * end;
  guint len;

  GumThumbWriter * output;
};

static gboolean gum_thumb_relocator_write_one_instruction (
    GumThumbRelocator * self);
static gboolean gum_thumb_relocator_rewrite_addh_if_pc_relative (
    GumThumbRelocator * self, GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_ldr_pc (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_b_imm (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_thumb_relocator_rewrite_bl_imm (GumThumbRelocator * self,
    GumCodeGenCtx * ctx);

void
gum_thumb_relocator_init (GumThumbRelocator * relocator,
                          gconstpointer input_code,
                          GumThumbWriter * output)
{
  relocator->input_insns = gum_new (GumArmInstruction,
      GUM_MAX_INPUT_INSN_COUNT);

  gum_thumb_relocator_reset (relocator, input_code, output);
}

void
gum_thumb_relocator_reset (GumThumbRelocator * relocator,
                           gconstpointer input_code,
                           GumThumbWriter * output)
{
  relocator->input_start = relocator->input_cur = input_code;
  relocator->output = output;

  relocator->inpos = relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_thumb_relocator_free (GumThumbRelocator * relocator)
{
  gum_free (relocator->input_insns);
}

static guint
gum_thumb_relocator_inpos (GumThumbRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_thumb_relocator_outpos (GumThumbRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_thumb_relocator_increment_inpos (GumThumbRelocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_thumb_relocator_increment_outpos (GumThumbRelocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_thumb_relocator_read_one (GumThumbRelocator * self,
                              const GumArmInstruction ** instruction)
{
  guint16 raw_insn;
  guint group, operation;
  GumArmInstruction * insn;

  if (self->eoi)
    return 0;

  raw_insn = *((guint16 *) self->input_cur);
  insn = &self->input_insns[gum_thumb_relocator_inpos (self)];

  group = (raw_insn >> 12) & 0b1111;
  operation = (raw_insn >> 8) & 0b1111;

  insn->mnemonic = GUM_ARM_UNKNOWN;
  insn->length = 2;

  switch (group)
  {
    case 0b0100:
      if (operation == 4)
        insn->mnemonic = GUM_ARM_ADDH;
      else if (operation >= 8)
        insn->mnemonic = GUM_ARM_LDRPC;
      break;

    case 0b1010:
      if (operation < 8)
        insn->mnemonic = GUM_ARM_ADDPC;
      else
        insn->mnemonic = GUM_ARM_ADDSP;
      break;

    case 0b1011:
      if (operation == 4 || operation == 5)
        insn->mnemonic = GUM_ARM_PUSH;
      break;

    case 0b1110:
      if (((raw_insn >> 11) & 1) == 0)
        insn->mnemonic = GUM_ARM_B_IMM_T2;
      break;

    case 0b1111:
    {
      guint32 wide_insn;

      insn->length = 4;

      wide_insn = ((guint32) raw_insn) << 16 |
          (guint32) *((guint16 *) (self->input_cur + 2));
      if ((wide_insn & 0xf800d000) == 0xf0009000)
        insn->mnemonic = GUM_ARM_B_IMM_T4;
      else if ((wide_insn & 0xf800d000) == 0xf000d000)
        insn->mnemonic = GUM_ARM_BL_IMM_T1;
      else if ((wide_insn & 0xf800d001) == 0xf000c000)
        insn->mnemonic = GUM_ARM_BLX_IMM_T2;

      break;
    }

    default:
      break;
  }

  insn->address = self->input_cur;

  gum_thumb_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->length;

  return self->input_cur - self->input_start;
}

GumArmInstruction *
gum_thumb_relocator_peek_next_write_insn (GumThumbRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_thumb_relocator_outpos (self)];
}

gpointer
gum_thumb_relocator_peek_next_write_source (GumThumbRelocator * self)
{
  GumArmInstruction * next;

  next = gum_thumb_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  g_assert_not_reached ();
  return NULL;
}

void
gum_thumb_relocator_skip_one (GumThumbRelocator * self)
{
  GumArmInstruction * next;

  next = gum_thumb_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_thumb_relocator_increment_outpos (self);
}

gboolean
gum_thumb_relocator_write_one (GumThumbRelocator * self)
{
  GumArmInstruction * cur;

  if ((cur = gum_thumb_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  return gum_thumb_relocator_write_one_instruction (self);
}

static gboolean
gum_thumb_relocator_write_one_instruction (GumThumbRelocator * self)
{
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_thumb_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_thumb_relocator_increment_outpos (self);

  ctx.len = ctx.insn->length;
  ctx.raw_insn = ctx.insn->address;
  ctx.start = ctx.insn->address;
  ctx.end = ctx.start + ctx.len;

  ctx.output = self->output;

  switch (ctx.insn->mnemonic)
  {
    case GUM_ARM_ADDH:
      rewritten = gum_thumb_relocator_rewrite_addh_if_pc_relative (self, &ctx);
      break;

    case GUM_ARM_LDRPC:
      rewritten = gum_thumb_relocator_rewrite_ldr_pc (self, &ctx);
      break;

    case GUM_ARM_B_IMM_T2:
    case GUM_ARM_B_IMM_T4:
      rewritten = gum_thumb_relocator_rewrite_b_imm (self, &ctx);
      break;

    case GUM_ARM_BL_IMM_T1:
    case GUM_ARM_BLX_IMM_T2:
      rewritten = gum_thumb_relocator_rewrite_bl_imm (self, &ctx);
      break;

    default:
      break;
  }

  if (!rewritten)
    gum_thumb_writer_put_bytes (ctx.output, ctx.start, ctx.len);

  return TRUE;
}

void
gum_thumb_relocator_write_all (GumThumbRelocator * self)
{
  guint count = 0;

  while (gum_thumb_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_thumb_relocator_eob (GumThumbRelocator * self)
{
  return self->eob;
}

gboolean
gum_thumb_relocator_eoi (GumThumbRelocator * self)
{
  return self->eoi;
}

gboolean
gum_thumb_relocator_can_relocate (gpointer address,
                                  guint min_bytes)
{
  guint8 * buf;
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_thumb_writer_init (&cw, buf);

  gum_thumb_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_thumb_relocator_free (&rl);

  gum_thumb_writer_free (&cw);

  return TRUE;
}

guint
gum_thumb_relocator_relocate (gpointer from,
                              guint min_bytes,
                              gpointer to)
{
  GumThumbWriter cw;
  GumThumbRelocator rl;
  guint reloc_bytes;

  gum_thumb_writer_init (&cw, to);

  gum_thumb_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_thumb_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_thumb_relocator_write_all (&rl);

  gum_thumb_relocator_free (&rl);
  gum_thumb_writer_free (&cw);

  return reloc_bytes;
}

static gboolean
gum_thumb_relocator_rewrite_addh_if_pc_relative (GumThumbRelocator * self,
                                                 GumCodeGenCtx * ctx)
{
  guint16 insn = *ctx->raw_insn;
  GumArmReg src_reg, dst_reg, temp_reg;
  gboolean dst_reg_is_upper;
  GumAddress absolute_pc;

  src_reg = (insn & 0x78) >> 3;
  if (src_reg != GUM_AREG_PC)
    return FALSE;

  dst_reg = insn & 0x7;
  dst_reg_is_upper = (insn & 0x80) != 0;
  if (dst_reg_is_upper)
    dst_reg += 8;

  if (dst_reg != GUM_AREG_R0)
    temp_reg = GUM_AREG_R0;
  else
    temp_reg = GUM_AREG_R1;

  absolute_pc = GPOINTER_TO_SIZE (ctx->start) + 4;

  gum_thumb_writer_put_push_regs (ctx->output, 1, temp_reg);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, temp_reg, absolute_pc);
  gum_thumb_writer_put_add_reg_reg (ctx->output, dst_reg, temp_reg);
  gum_thumb_writer_put_pop_regs (ctx->output, 1, temp_reg);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_ldr_pc (GumThumbRelocator * self,
                                    GumCodeGenCtx * ctx)
{
  guint16 insn = *ctx->raw_insn;
  GumArmReg reg;
  GumAddress absolute_pc;

  reg = (insn & 0x0700) >> 8;

  absolute_pc = (GPOINTER_TO_SIZE (ctx->start) + 4) & ~(4 - 1);
  absolute_pc += (insn & 0x00ff) * 4;

  gum_thumb_writer_put_ldr_reg_address (ctx->output, reg, absolute_pc);
  gum_thumb_writer_put_ldr_reg_reg (ctx->output, reg, reg);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_b_imm (GumThumbRelocator * self,
                                   GumCodeGenCtx * ctx)
{
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;

  switch (ctx->insn->mnemonic)
  {
    case GUM_ARM_B_IMM_T2:
    {
      guint16 insn = *ctx->raw_insn;
      guint32 imm11;

      imm11 = insn & 0b11111111111;

      distance.u = ((imm11 & 0b10000000000) ? 0xfffff000 : 0x00000000) |
          (imm11 << 1);

      break;
    }

    case GUM_ARM_B_IMM_T4:
    {
      guint32 insn, s, j1, j2, i1, i2, imm10_h, imm11_l;

      insn =
          ((guint32) *(ctx->raw_insn)) << 16 | (guint32) *(ctx->raw_insn + 1);

      s = (insn >> 26) & 1;
      j1 = (insn >> 13) & 1;
      j2 = (insn >> 11) & 1;
      i1 = ~(j1 ^ s) & 1;
      i2 = ~(j2 ^ s) & 1;
      imm10_h = (insn >> 16) & 0b1111111111;
      imm11_l = insn & 0b11111111111;

      distance.u = (s ? 0xff000000 : 0x00000000) |
          (i1 << 23) | (i2 << 22) | (imm10_h << 12) | (imm11_l << 1);

      break;
    }

    default:
      g_assert_not_reached ();
      break;
  }

  absolute_target = GPOINTER_TO_SIZE (ctx->start) + 4 + distance.i;

  gum_thumb_writer_put_push_regs (ctx->output, 1, GUM_AREG_R0);
  gum_thumb_writer_put_push_regs (ctx->output, 1, GUM_AREG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, GUM_AREG_R0,
      absolute_target);
  gum_thumb_writer_put_str_reg_reg_offset (ctx->output, GUM_AREG_R0,
      GUM_AREG_SP, 4);
  gum_thumb_writer_put_pop_regs (ctx->output, 2, GUM_AREG_R0, GUM_AREG_PC);

  return TRUE;
}

static gboolean
gum_thumb_relocator_rewrite_bl_imm (GumThumbRelocator * self,
                                    GumCodeGenCtx * ctx)
{
  guint32 insn, s, j1, j2, i1, i2, imm10_h, imm11_l;
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;

  insn = ((guint32) *(ctx->raw_insn)) << 16 | (guint32) *(ctx->raw_insn + 1);

  /* GUM_ARM_BL_IMM_T1 and GUM_ARM_BLX_IMM_T2 */
  s = (insn >> 26) & 1;
  j1 = (insn >> 13) & 1;
  j2 = (insn >> 11) & 1;
  i1 = ~(j1 ^ s) & 1;
  i2 = ~(j2 ^ s) & 1;
  imm10_h = (insn >> 16) & 0b1111111111;
  imm11_l = insn & 0b11111111111;

  distance.u = (s ? 0xff000000 : 0x00000000) |
      (i1 << 23) | (i2 << 22) | (imm10_h << 12) | (imm11_l << 1);

  absolute_target = GPOINTER_TO_SIZE (ctx->start) + 4 + distance.i;

  gum_thumb_writer_put_push_regs (ctx->output, 1, GUM_AREG_R0);
  gum_thumb_writer_put_ldr_reg_address (ctx->output, GUM_AREG_R0,
      absolute_target);
  gum_thumb_writer_put_mov_reg_reg (ctx->output, GUM_AREG_LR, GUM_AREG_R0);
  gum_thumb_writer_put_pop_regs (ctx->output, 1, GUM_AREG_R0);
  gum_thumb_writer_put_blx_reg (ctx->output, GUM_AREG_LR);

  return TRUE;
}
