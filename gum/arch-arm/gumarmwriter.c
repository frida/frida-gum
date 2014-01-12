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

#include "gumarmwriter.h"

#include <string.h>

#define GUM_ARM_WRITER_NUM_RESERVED_U32_REFS (16)

typedef struct _GumArmU32Ref GumArmU32Ref;

struct _GumArmU32Ref
{
  guint32 * insn;
  guint32 val;
};

static void gum_arm_writer_put_instruction (GumArmWriter * self,
    guint32 insn);

void
gum_arm_writer_init (GumArmWriter * writer,
                     gpointer code_address)
{
  writer->u32_refs = gum_array_sized_new (FALSE, FALSE,
      sizeof (GumArmU32Ref), GUM_ARM_WRITER_NUM_RESERVED_U32_REFS);

  gum_arm_writer_reset (writer, code_address);
}

void
gum_arm_writer_reset (GumArmWriter * writer,
                      gpointer code_address)
{
  writer->base = code_address;
  writer->code = code_address;
}

void
gum_arm_writer_free (GumArmWriter * writer)
{
  gum_arm_writer_flush (writer);

  gum_array_free (writer->u32_refs, TRUE);
}

gpointer
gum_arm_writer_cur (GumArmWriter * self)
{
  return self->code;
}

guint
gum_arm_writer_offset (GumArmWriter * self)
{
  return (self->code - self->base) * sizeof (guint32);
}

void
gum_arm_writer_skip (GumArmWriter * self,
                     guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
}

void
gum_arm_writer_flush (GumArmWriter * self)
{
  guint32 * first_slot, * last_slot;
  guint ref_idx;

  if (self->u32_refs->len == 0)
    return;

  first_slot = self->code;
  last_slot = first_slot;

  for (ref_idx = 0; ref_idx != self->u32_refs->len; ref_idx++)
  {
    GumArmU32Ref * r;
    guint32 * cur_slot;
    gssize distance_in_words;
    guint32 insn;

    r = &g_array_index (self->u32_refs, GumArmU32Ref, ref_idx);

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

    distance_in_words = cur_slot - (r->insn + 2);

    insn = GUINT32_FROM_LE (*r->insn);
    insn |= ABS (distance_in_words) * 4;
    if (distance_in_words >= 0)
      insn |= 1 << 23;
    *r->insn = GUINT32_TO_LE (insn);
  }
  gum_array_set_size (self->u32_refs, 0);

  self->code = last_slot;
}

static void
gum_arm_writer_mark_u32_reference_here (GumArmWriter * self,
                                        guint32 val)
{
  GumArmU32Ref r;

  r.insn = self->code;
  r.val = val;

  gum_array_append_val (self->u32_refs, r);
}

void
gum_arm_writer_put_ldr_reg_address (GumArmWriter * self,
                                    GumArmReg reg,
                                    GumAddress address)
{
  gum_arm_writer_put_ldr_reg_u32 (self, reg, (guint32) address);
}

void
gum_arm_writer_put_ldr_reg_u32 (GumArmWriter * self,
                                GumArmReg reg,
                                guint32 val)
{
  gum_arm_writer_mark_u32_reference_here (self, val);
  gum_arm_writer_put_instruction (self, 0xe51f0000 | (reg << 12));
}

void
gum_arm_writer_put_nop (GumArmWriter * self)
{
  gum_arm_writer_put_instruction (self, 0xe1a00000);
}

void
gum_arm_writer_put_bytes (GumArmWriter * self,
                          const guint8 * data,
                          guint n)
{
  g_assert (n % 2 == 0);

  memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
}

static void
gum_arm_writer_put_instruction (GumArmWriter * self,
                                guint32 insn)
{
  *self->code++ = GUINT32_TO_LE (insn);
}

