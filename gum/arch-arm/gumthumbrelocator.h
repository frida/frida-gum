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

#ifndef __GUM_THUMB_RELOCATOR_H__
#define __GUM_THUMB_RELOCATOR_H__

#include "gumdefs.h"

#include "gumthumbwriter.h"

G_BEGIN_DECLS

typedef struct _GumThumbRelocator GumThumbRelocator;

struct _GumThumbRelocator
{
  const guint8 * input_start;
  const guint8 * input_cur;
  GumArmInstruction * input_insns;
  GumThumbWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

void gum_thumb_relocator_init (GumThumbRelocator * relocator,
    gconstpointer input_code, GumThumbWriter * output);
void gum_thumb_relocator_reset (GumThumbRelocator * relocator,
    gconstpointer input_code, GumThumbWriter * output);
void gum_thumb_relocator_free (GumThumbRelocator * relocator);

guint gum_thumb_relocator_read_one (GumThumbRelocator * self, const GumArmInstruction ** instruction);

GumArmInstruction * gum_thumb_relocator_peek_next_write_insn (GumThumbRelocator * self);
gpointer gum_thumb_relocator_peek_next_write_source (GumThumbRelocator * self);
void gum_thumb_relocator_skip_one (GumThumbRelocator * self);
gboolean gum_thumb_relocator_write_one (GumThumbRelocator * self);
void gum_thumb_relocator_write_all (GumThumbRelocator * self);

gboolean gum_thumb_relocator_eob (GumThumbRelocator * self);
gboolean gum_thumb_relocator_eoi (GumThumbRelocator * self);

gboolean gum_thumb_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_thumb_relocator_relocate (gpointer from, guint min_bytes, gpointer to);

G_END_DECLS

#endif
