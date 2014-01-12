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

#include "gumarmrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const GumArmInstruction * insn;
  const guint32 * raw_insn;
  const guint8 * start;
  const guint8 * end;
  guint len;

  GumArmWriter * output;
};

static gboolean gum_arm_relocator_write_one_instruction (
    GumArmRelocator * self);
static gboolean gum_arm_relocator_rewrite_b_imm24 (GumArmRelocator * self,
    GumCodeGenCtx * ctx);

void
gum_arm_relocator_init (GumArmRelocator * relocator,
                        gconstpointer input_code,
                        GumArmWriter * output)
{
  relocator->input_insns = gum_new (GumArmInstruction,
      GUM_MAX_INPUT_INSN_COUNT);

  gum_arm_relocator_reset (relocator, input_code, output);
}

void
gum_arm_relocator_reset (GumArmRelocator * relocator,
                         gconstpointer input_code,
                         GumArmWriter * output)
{
  relocator->input_start = relocator->input_cur = input_code;
  relocator->output = output;

  relocator->inpos = relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_arm_relocator_free (GumArmRelocator * relocator)
{
  gum_free (relocator->input_insns);
}

static guint
gum_arm_relocator_inpos (GumArmRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_arm_relocator_outpos (GumArmRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_arm_relocator_increment_inpos (GumArmRelocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_arm_relocator_increment_outpos (GumArmRelocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_arm_relocator_read_one (GumArmRelocator * self,
                            const GumArmInstruction ** instruction)
{
  guint32 raw_insn;
  guint category;
  GumArmInstruction * insn;

  if (self->eoi)
    return 0;

  raw_insn = *((guint32 *) self->input_cur);
  insn = &self->input_insns[gum_arm_relocator_inpos (self)];

  category = (raw_insn >> 25) & 0b111;

  insn->mnemonic = GUM_ARM_UNKNOWN;
  insn->length = 4;

  switch (category)
  {
    case 0b000: /* data processing */
    case 0b001:
    {
      guint opcode = (raw_insn >> 21) & 0b1111;
      switch (opcode)
      {
        case 0b1101:
          insn->mnemonic = GUM_ARM_MOV;
          break;
      }
      break;
    }
    case 0b010: /* load/store */
      break;
    case 0b100: /* load/store multiple */
    {
      guint base_register = (raw_insn >> 16) & 0b1111;
      guint is_load = (raw_insn >> 20) & 1;
      if (base_register == GUM_AREG_SP)
        insn->mnemonic = is_load ? GUM_ARM_POP : GUM_ARM_PUSH;
      break;
    }
    case 0b101: /* control */
      insn->mnemonic =
          ((raw_insn & 0x1000000) == 0) ? GUM_ARM_B_IMM24 : GUM_ARM_BL_IMM24;
      break;
  }

  insn->address = self->input_cur;

  gum_arm_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->length;

  return self->input_cur - self->input_start;
}

GumArmInstruction *
gum_arm_relocator_peek_next_write_insn (GumArmRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_arm_relocator_outpos (self)];
}

gpointer
gum_arm_relocator_peek_next_write_source (GumArmRelocator * self)
{
  GumArmInstruction * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  g_assert_not_reached ();
  return NULL;
}

void
gum_arm_relocator_skip_one (GumArmRelocator * self)
{
  GumArmInstruction * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_arm_relocator_increment_outpos (self);
}

gboolean
gum_arm_relocator_write_one (GumArmRelocator * self)
{
  GumArmInstruction * cur;

  if ((cur = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  return gum_arm_relocator_write_one_instruction (self);
}

static gboolean
gum_arm_relocator_write_one_instruction (GumArmRelocator * self)
{
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm_relocator_increment_outpos (self);

  ctx.len = ctx.insn->length;
  ctx.raw_insn = ctx.insn->address;
  ctx.start = ctx.insn->address;
  ctx.end = ctx.start + ctx.len;

  ctx.output = self->output;

  switch (ctx.insn->mnemonic)
  {
    case GUM_ARM_B_IMM24:
    case GUM_ARM_BL_IMM24:
      rewritten = gum_arm_relocator_rewrite_b_imm24 (self, &ctx);
      break;

    default:
      break;
  }

  if (!rewritten)
    gum_arm_writer_put_bytes (ctx.output, ctx.start, ctx.len);

  return TRUE;
}

void
gum_arm_relocator_write_all (GumArmRelocator * self)
{
  guint count = 0;

  while (gum_arm_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_arm_relocator_eob (GumArmRelocator * self)
{
  return self->eob;
}

gboolean
gum_arm_relocator_eoi (GumArmRelocator * self)
{
  return self->eoi;
}

gboolean
gum_arm_relocator_can_relocate (gpointer address,
                                guint min_bytes)
{
  guint8 * buf;
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_arm_writer_init (&cw, buf);

  gum_arm_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_free (&rl);

  gum_arm_writer_free (&cw);

  return TRUE;
}

guint
gum_arm_relocator_relocate (gpointer from,
                            guint min_bytes,
                            gpointer to)
{
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  gum_arm_writer_init (&cw, to);

  gum_arm_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_write_all (&rl);

  gum_arm_relocator_free (&rl);
  gum_arm_writer_free (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm_relocator_rewrite_b_imm24 (GumArmRelocator * self,
                                   GumCodeGenCtx * ctx)
{
  guint32 raw_insn;
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;

  raw_insn = *ctx->raw_insn;
  if ((raw_insn & 0x00800000) != 0)
    distance.u = 0xfc000000 | ((raw_insn & 0x00ffffff) << 2);
  else
    distance.u = ((raw_insn & 0x007fffff) << 2);

  absolute_target = GPOINTER_TO_SIZE (ctx->start) + 8 + distance.i;

  gum_arm_writer_put_ldr_reg_address (ctx->output, GUM_AREG_PC, absolute_target);

  return TRUE;
}
