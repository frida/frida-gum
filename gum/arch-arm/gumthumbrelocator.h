/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_THUMB_RELOCATOR_H__
#define __GUM_THUMB_RELOCATOR_H__

#include "gumthumbwriter.h"

#include <capstone/capstone.h>

G_BEGIN_DECLS

typedef struct _GumThumbRelocator GumThumbRelocator;

struct _GumThumbRelocator
{
  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  GumAddress input_pc;
  cs_insn ** input_insns;
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

guint gum_thumb_relocator_read_one (GumThumbRelocator * self,
    const cs_insn ** instruction);

cs_insn * gum_thumb_relocator_peek_next_write_insn (GumThumbRelocator * self);
gpointer gum_thumb_relocator_peek_next_write_source (GumThumbRelocator * self);
void gum_thumb_relocator_skip_one (GumThumbRelocator * self);
gboolean gum_thumb_relocator_write_one (GumThumbRelocator * self);
void gum_thumb_relocator_write_all (GumThumbRelocator * self);

gboolean gum_thumb_relocator_eob (GumThumbRelocator * self);
gboolean gum_thumb_relocator_eoi (GumThumbRelocator * self);

gboolean gum_thumb_relocator_can_relocate (gpointer address, guint min_bytes);
guint gum_thumb_relocator_relocate (gpointer from, guint min_bytes,
    gpointer to);

G_END_DECLS

#endif
