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

#include "gumthumbwriter.h"

#include <string.h>

#define GUM_THUMB_WRITER_NUM_RESERVED_U32_REFS (16)

typedef struct _GumThumbU32Ref GumThumbU32Ref;

struct _GumThumbU32Ref
{
  guint16 * insn;
  guint32 val;
};

static void gum_thumb_writer_put_instruction (GumThumbWriter * self,
    guint16 insn);

void
gum_thumb_writer_init (GumThumbWriter * writer,
                       gpointer code_address)
{
  writer->u32_refs = gum_array_sized_new (FALSE, FALSE,
      sizeof (GumThumbU32Ref), GUM_THUMB_WRITER_NUM_RESERVED_U32_REFS);

  gum_thumb_writer_reset (writer, code_address);
}

void
gum_thumb_writer_reset (GumThumbWriter * writer,
                        gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
}

void
gum_thumb_writer_free (GumThumbWriter * writer)
{
  gum_thumb_writer_flush (writer);

  gum_array_free (writer->u32_refs, TRUE);
}

gpointer
gum_thumb_writer_cur (GumThumbWriter * self)
{
  return self->code;
}

guint
gum_thumb_writer_offset (GumThumbWriter * self)
{
  return (self->code - self->base) * sizeof (guint16);
}

void
gum_thumb_writer_flush (GumThumbWriter * self)
{
  guint32 * first_slot, * last_slot;
  guint ref_idx;

  if (self->u32_refs->len == 0)
    return;

  if ((GPOINTER_TO_SIZE (self->code) & 2) == 0)
    first_slot = (guint32 *) (self->code + 0);
  else
    first_slot = (guint32 *) (self->code + 1);
  last_slot = first_slot;

  for (ref_idx = 0; ref_idx != self->u32_refs->len; ref_idx++)
  {
    GumThumbU32Ref * r;
    guint32 * cur_slot;
    gsize distance_in_words;

    r = &g_array_index (self->u32_refs, GumThumbU32Ref, ref_idx);

    for (cur_slot = first_slot; cur_slot != last_slot; cur_slot++)
    {
      if (*cur_slot == r->val)
        break;
    }

    if (cur_slot == last_slot)
    {
      *cur_slot = r->val;
      last_slot++;
    }

    distance_in_words = cur_slot - (guint32 *) (r->insn + 1);
    *r->insn = GUINT16_TO_LE (GUINT16_FROM_LE (*r->insn) | distance_in_words);
  }
  gum_array_set_size (self->u32_refs, 0);

  self->code = (guint16 *) last_slot;
}

static void
gum_thumb_writer_mark_u32_reference_here (GumThumbWriter * self,
                                          guint32 val)
{
  GumThumbU32Ref r;

  r.insn = self->code;
  r.val = val;

  gum_array_append_val (self->u32_refs, r);
}

void
gum_thumb_writer_put_bx_reg (GumThumbWriter * self,
                             GumThumbReg reg)
{
  gum_thumb_writer_put_instruction (self, 0x4700 | (reg << 3));
}

void
gum_thumb_writer_put_blx_reg (GumThumbWriter * self,
                              GumThumbReg reg)
{
  gum_thumb_writer_put_instruction (self, 0x4780 | (reg << 3));
}

void
gum_thumb_writer_put_push_regs (GumThumbWriter * self,
                                guint n_regs,
                                GumThumbReg first_reg,
                                ...)
{
  guint16 insn = 0xb400;
  va_list vl;
  GumThumbReg cur_reg;
  guint reg_idx;

  g_assert_cmpuint (n_regs, !=, 0);

  va_start (vl, first_reg);
  cur_reg = first_reg;
  for (reg_idx = 0; reg_idx != n_regs; reg_idx++)
  {
    g_assert ((cur_reg >= GUM_TREG_R0 && cur_reg <= GUM_TREG_R7) ||
        cur_reg == GUM_TREG_LR);

    if (cur_reg == GUM_TREG_LR)
      insn |= 0x100;
    else
      insn |= (1 << (cur_reg - GUM_TREG_R0));

    cur_reg = va_arg (vl, GumThumbReg);
  }
  va_end (vl);

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_pop_regs (GumThumbWriter * self,
                               guint n_regs,
                               GumThumbReg first_reg,
                               ...)
{
  guint16 insn = 0xbc00;
  va_list vl;
  GumThumbReg cur_reg;
  guint reg_idx;

  g_assert_cmpuint (n_regs, !=, 0);

  va_start (vl, first_reg);
  cur_reg = first_reg;
  for (reg_idx = 0; reg_idx != n_regs; reg_idx++)
  {
    g_assert ((cur_reg >= GUM_TREG_R0 && cur_reg <= GUM_TREG_R7) ||
        cur_reg == GUM_TREG_PC);

    if (cur_reg == GUM_TREG_PC)
      insn |= 0x100;
    else
      insn |= (1 << (cur_reg - GUM_TREG_R0));

    cur_reg = va_arg (vl, GumThumbReg);
  }
  va_end (vl);

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_ldr_reg_address (GumThumbWriter * self,
                                      GumThumbReg reg,
                                      GumAddress address)
{
  gum_thumb_writer_put_ldr_reg_u32 (self, reg, (guint32) address);
}

void
gum_thumb_writer_put_ldr_reg_u32 (GumThumbWriter * self,
                                  GumThumbReg reg,
                                  guint32 val)
{
  gum_thumb_writer_mark_u32_reference_here (self, val);
  gum_thumb_writer_put_instruction (self, 0x4800 | (reg << 8));
}

void
gum_thumb_writer_put_ldr_reg_reg (GumThumbWriter * self,
                                  GumThumbReg dst_reg,
                                  GumThumbReg src_reg)
{
  gum_thumb_writer_put_ldr_reg_reg_offset (self, dst_reg, src_reg, 0);
}

void
gum_thumb_writer_put_ldr_reg_reg_offset (GumThumbWriter * self,
                                         GumThumbReg dst_reg,
                                         GumThumbReg src_reg,
                                         guint8 src_offset)
{
  guint16 insn;

  g_assert (src_offset % 4 == 0);

  if (src_reg == GUM_TREG_SP)
  {
    g_assert_cmpuint (src_offset, <=, 1020);

    insn = 0x9800 | (dst_reg << 8) | (src_offset / 4);
  }
  else
  {
    g_assert_cmpuint (src_offset, <=, 124);

    insn = 0x6800 | (src_offset / 4) << 6 | (src_reg << 3) | dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self,
                                  GumThumbReg dst_reg,
                                  GumThumbReg src_reg)
{
  guint16 insn;

  if (dst_reg <= GUM_TREG_R7 && src_reg <= GUM_TREG_R7)
  {
    insn = 0x1c00 | (src_reg << 3) | dst_reg;
  }
  else
  {
    guint16 dst_is_high;

    if (dst_reg > GUM_TREG_R7)
    {
      dst_is_high = 1;
      dst_reg -= GUM_TREG_R7 + 1;
    }
    else
    {
      dst_is_high = 0;
    }

    insn = 0x4600 | (dst_is_high << 7) | (src_reg << 3) | dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self,
                                 GumThumbReg dst_reg,
                                 guint8 imm_value)
{
  gum_thumb_writer_put_instruction (self, 0x2000 | (dst_reg << 8) | imm_value);
}

void
gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self,
                                  GumThumbReg dst_reg,
                                  gssize imm_value)
{
  guint16 insn, sign_mask = 0x0000;

  if (dst_reg == GUM_TREG_SP)
  {
    g_assert (imm_value % 4 == 0);

    if (imm_value < 0)
      sign_mask = 0x0080;

    insn = 0xb000 | sign_mask | ABS (imm_value / 4);
  }
  else
  {
    if (imm_value < 0)
      sign_mask = 0x0800;

    insn = 0x3000 | sign_mask | (dst_reg << 8) | ABS (imm_value);
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_add_reg_reg (GumThumbWriter * self,
                                  GumThumbReg dst_reg,
                                  GumThumbReg src_reg)
{
  gum_thumb_writer_put_add_reg_reg_reg (self, dst_reg, dst_reg, src_reg);
}

void
gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self,
                                      GumThumbReg dst_reg,
                                      GumThumbReg left_reg,
                                      GumThumbReg right_reg)
{
  guint16 insn;

  insn = 0x1800 | (right_reg << 6) | (left_reg << 3) | dst_reg;

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self,
                                      GumThumbReg dst_reg,
                                      GumThumbReg left_reg,
                                      gssize right_value)
{
  guint16 insn;

  if (left_reg == dst_reg)
  {
    gum_thumb_writer_put_add_reg_imm (self, dst_reg, right_value);
    return;
  }

  if (left_reg == GUM_TREG_SP || left_reg == GUM_TREG_PC)
  {
    guint16 base_mask;

    g_assert_cmpint (right_value, >=, 0);
    g_assert (right_value % 4 == 0);

    if (left_reg == GUM_TREG_SP)
      base_mask = 0x0800;
    else
      base_mask = 0x0000;

    insn = 0xa000 | base_mask | (dst_reg << 8) | (right_value / 4);
  }
  else
  {
    guint16 sign_mask = 0x0000;

    g_assert_cmpuint (ABS (right_value), <=, 7);

    if (right_value < 0)
      sign_mask = 0x0200;

    insn = 0x1c00 | sign_mask | (ABS (right_value) << 6) | (left_reg << 3) |
        dst_reg;
  }

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self,
                                  GumThumbReg dst_reg,
                                  gssize imm_value)
{
  gum_thumb_writer_put_add_reg_imm (self, dst_reg, -imm_value);
}

void
gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self,
                                      GumThumbReg dst_reg,
                                      GumThumbReg left_reg,
                                      GumThumbReg right_reg)
{
  guint16 insn;

  insn = 0x1a00 | (right_reg << 6) | (left_reg << 3) | dst_reg;

  gum_thumb_writer_put_instruction (self, insn);
}

void
gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self,
                                      GumThumbReg dst_reg,
                                      GumThumbReg left_reg,
                                      gssize right_value)
{
  gum_thumb_writer_put_add_reg_reg_imm (self, dst_reg, left_reg, -right_value);
}

void
gum_thumb_writer_put_nop (GumThumbWriter * self)
{
  gum_thumb_writer_put_instruction (self, 0x46c0);
}

void
gum_thumb_writer_put_bytes (GumThumbWriter * self,
                            const guint8 * data,
                            guint n)
{
  memcpy (self->code, data, n);
  self->code += n;
}

static void
gum_thumb_writer_put_instruction (GumThumbWriter * self,
                                  guint16 insn)
{
  *self->code++ = GUINT16_TO_LE (insn);
}

