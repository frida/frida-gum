/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_ARM64_RELOCATOR_H__
#define __GUM_ARM64_RELOCATOR_H__

#include "gumdefs.h"

#include "gumarm64writer.h"

G_BEGIN_DECLS

typedef struct _GumArm64Relocator GumArm64Relocator;

struct _GumArm64Relocator
{
  const guint8 * input_start;
  const guint8 * input_cur;
  GumArm64Instruction * input_insns;
  GumArm64Writer * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

void gum_arm64_relocator_init (GumArm64Relocator * relocator,
    gconstpointer input_code, GumArm64Writer * output);
void gum_arm64_relocator_reset (GumArm64Relocator * relocator,
    gconstpointer input_code, GumArm64Writer * output);
void gum_arm64_relocator_free (GumArm64Relocator * relocator);

guint gum_arm64_relocator_read_one (GumArm64Relocator * self,
    const GumArm64Instruction ** instruction);

GumArm64Instruction * gum_arm64_relocator_peek_next_write_insn (
    GumArm64Relocator * self);
gpointer gum_arm64_relocator_peek_next_write_source (GumArm64Relocator * self);
void gum_arm64_relocator_skip_one (GumArm64Relocator * self);
gboolean gum_arm64_relocator_write_one (GumArm64Relocator * self);
void gum_arm64_relocator_write_all (GumArm64Relocator * self);

gboolean gum_arm64_relocator_eob (GumArm64Relocator * self);
gboolean gum_arm64_relocator_eoi (GumArm64Relocator * self);

gboolean gum_arm64_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_arm64_relocator_relocate (gpointer from, guint min_bytes,
    gpointer to);

G_END_DECLS

#endif
