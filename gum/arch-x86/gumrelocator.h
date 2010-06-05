/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_RELOCATOR_H__
#define __GUM_RELOCATOR_H__

#include "gumdefs.h"

#include "gumcodewriter.h"

#include <udis86.h>

G_BEGIN_DECLS

typedef struct _GumRelocator GumRelocator;

struct _GumRelocator
{
  const guint8 * input_start;
  const guint8 * input_cur;
  ud_t * input_insns;
  GumCodeWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

void gum_relocator_init (GumRelocator * relocator, const guint8 * input_code,
    GumCodeWriter * output);
void gum_relocator_reset (GumRelocator * relocator, const guint8 * input_code,
    GumCodeWriter * output);
void gum_relocator_free (GumRelocator * relocator);

guint gum_relocator_read_one (GumRelocator * self, const ud_t ** insn);

ud_t * gum_relocator_peek_next_write_insn (GumRelocator * self);
gpointer gum_relocator_peek_next_write_source (GumRelocator * self);
void gum_relocator_skip_one (GumRelocator * self);
void gum_relocator_skip_one_no_label (GumRelocator * self);
gboolean gum_relocator_write_one (GumRelocator * self);
gboolean gum_relocator_write_one_no_label (GumRelocator * self);
void gum_relocator_write_all (GumRelocator * self);

gboolean gum_relocator_eob (GumRelocator * self);
gboolean gum_relocator_eoi (GumRelocator * self);

gboolean gum_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_relocator_relocate (gpointer from, guint min_bytes, gpointer to);

G_END_DECLS

#endif
