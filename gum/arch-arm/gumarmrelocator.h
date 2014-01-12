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

#ifndef __GUM_ARM_RELOCATOR_H__
#define __GUM_ARM_RELOCATOR_H__

#include "gumdefs.h"

#include "gumarmwriter.h"

G_BEGIN_DECLS

typedef struct _GumArmRelocator GumArmRelocator;

struct _GumArmRelocator
{
  const guint8 * input_start;
  const guint8 * input_cur;
  GumArmInstruction * input_insns;
  GumArmWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

void gum_arm_relocator_init (GumArmRelocator * relocator,
    gconstpointer input_code, GumArmWriter * output);
void gum_arm_relocator_reset (GumArmRelocator * relocator,
    gconstpointer input_code, GumArmWriter * output);
void gum_arm_relocator_free (GumArmRelocator * relocator);

guint gum_arm_relocator_read_one (GumArmRelocator * self, const GumArmInstruction ** instruction);

GumArmInstruction * gum_arm_relocator_peek_next_write_insn (GumArmRelocator * self);
gpointer gum_arm_relocator_peek_next_write_source (GumArmRelocator * self);
void gum_arm_relocator_skip_one (GumArmRelocator * self);
gboolean gum_arm_relocator_write_one (GumArmRelocator * self);
void gum_arm_relocator_write_all (GumArmRelocator * self);

gboolean gum_arm_relocator_eob (GumArmRelocator * self);
gboolean gum_arm_relocator_eoi (GumArmRelocator * self);

gboolean gum_arm_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_arm_relocator_relocate (gpointer from, guint min_bytes, gpointer to);

G_END_DECLS

#endif
