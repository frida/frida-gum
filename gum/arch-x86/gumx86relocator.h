/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_X86_RELOCATOR_H__
#define __GUM_X86_RELOCATOR_H__

#include "gumx86writer.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumX86Relocator GumX86Relocator;

struct _GumX86Relocator
{
  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  cs_insn ** input_insns;
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

guint gum_x86_relocator_read_one (GumX86Relocator * self,
    const cs_insn ** instruction);

cs_insn * gum_x86_relocator_peek_next_write_insn (GumX86Relocator * self);
gpointer gum_x86_relocator_peek_next_write_source (GumX86Relocator * self);
void gum_x86_relocator_skip_one (GumX86Relocator * self);
void gum_x86_relocator_skip_one_no_label (GumX86Relocator * self);
gboolean gum_x86_relocator_write_one (GumX86Relocator * self);
gboolean gum_x86_relocator_write_one_no_label (GumX86Relocator * self);
void gum_x86_relocator_write_all (GumX86Relocator * self);

gboolean gum_x86_relocator_eob (GumX86Relocator * self);
gboolean gum_x86_relocator_eoi (GumX86Relocator * self);

gboolean gum_x86_relocator_can_relocate (gpointer address, guint min_bytes,
    guint * maximum);
guint gum_x86_relocator_relocate (gpointer from, guint min_bytes, gpointer to);

G_END_DECLS

#endif
