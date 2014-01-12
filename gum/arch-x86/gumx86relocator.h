/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_X86_RELOCATOR_H__
#define __GUM_X86_RELOCATOR_H__

#include "gumdefs.h"

#include "gumx86writer.h"

#include <udis86.h>

G_BEGIN_DECLS

typedef struct _GumX86Relocator GumX86Relocator;

struct _GumX86Relocator
{
  const guint8 * input_start;
  const guint8 * input_cur;
  ud_t * input_insns;
  GumX86Writer * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

void gum_x86_relocator_init (GumX86Relocator * relocator,
    const guint8 * input_code, GumX86Writer * output);
void gum_x86_relocator_reset (GumX86Relocator * relocator,
    const guint8 * input_code, GumX86Writer * output);
void gum_x86_relocator_free (GumX86Relocator * relocator);

guint gum_x86_relocator_read_one (GumX86Relocator * self, const ud_t ** insn);

ud_t * gum_x86_relocator_peek_next_write_insn (GumX86Relocator * self);
gpointer gum_x86_relocator_peek_next_write_source (GumX86Relocator * self);
void gum_x86_relocator_skip_one (GumX86Relocator * self);
void gum_x86_relocator_skip_one_no_label (GumX86Relocator * self);
gboolean gum_x86_relocator_write_one (GumX86Relocator * self);
gboolean gum_x86_relocator_write_one_no_label (GumX86Relocator * self);
void gum_x86_relocator_write_all (GumX86Relocator * self);

gboolean gum_x86_relocator_eob (GumX86Relocator * self);
gboolean gum_x86_relocator_eoi (GumX86Relocator * self);

gboolean gum_x86_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_x86_relocator_relocate (gpointer from, guint min_bytes, gpointer to);

G_END_DECLS

#endif
