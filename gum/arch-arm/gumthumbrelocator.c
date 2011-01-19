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

  group = (raw_insn >> 12) & 0xf;
  operation = (raw_insn >> 8) & 0xf;

  insn->mnemonic = GUM_ARM_UNKNOWN;
  insn->length = 2;

  switch (group)
  {
    case 0x4:
      if (operation == 4)
        insn->mnemonic = GUM_ARM_ADDH;
      else if (operation >= 8)
        insn->mnemonic = GUM_ARM_LDRPC;
      break;

    case 0xa:
      if (operation < 8)
        insn->mnemonic = GUM_ARM_ADDPC;
      else
        insn->mnemonic = GUM_ARM_ADDSP;
      break;

    case 0xb:
      if (operation == 4 || operation == 5)
        insn->mnemonic = GUM_ARM_PUSH;
      break;

    case 0xf:
      insn->length = 4;
      break;

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
  guint16 raw_insn;
  GumArmReg src_reg, dst_reg, temp_reg;
  gboolean dst_reg_is_upper;
  GumAddress absolute_pc;

  raw_insn = *ctx->raw_insn;

  src_reg = (raw_insn & 0x78) >> 3;
  if (src_reg != GUM_AREG_PC)
    return FALSE;

  dst_reg = raw_insn & 0x7;
  dst_reg_is_upper = (raw_insn & 0x80) != 0;
  if (dst_reg_is_upper)
    dst_reg += 8;

  if (dst_reg != GUM_AREG_R0)
    temp_reg = GUM_AREG_R0;
  else
    temp_reg = GUM_AREG_R1;

  absolute_pc = GPOINTER_TO_SIZE (ctx->end);
  if (absolute_pc % 4 != 0)
    absolute_pc += 2;

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
  guint16 raw_insn;
  GumArmReg reg;
  GumAddress absolute_pc;

  raw_insn = *ctx->raw_insn;

  reg = (raw_insn & 0x0700) >> 8;

  absolute_pc = (raw_insn & 0x00ff) * 4;
  absolute_pc += GPOINTER_TO_SIZE (ctx->end);
  if (absolute_pc % 4 != 0)
    absolute_pc += 2;

  gum_thumb_writer_put_ldr_reg_address (ctx->output, reg, absolute_pc);
  gum_thumb_writer_put_ldr_reg_reg (ctx->output, reg, reg);

  return TRUE;
}
