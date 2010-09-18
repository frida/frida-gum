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
gum_thumb_writer_put_ldr_u32 (GumThumbWriter * self,
                              GumThumbReg reg,
                              guint32 val)
{
  gum_thumb_writer_mark_u32_reference_here (self, val);
  gum_thumb_writer_put_instruction (self, 0x4800 | (reg << 8));
}

static void
gum_thumb_writer_put_instruction (GumThumbWriter * self,
                                  guint16 insn)
{
  *self->code++ = GUINT16_TO_LE (insn);
}

