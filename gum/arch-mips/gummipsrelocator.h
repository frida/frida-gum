/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MIPS_RELOCATOR_H__
#define __GUM_MIPS_RELOCATOR_H__

#include "gummipswriter.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumMipsRelocator GumMipsRelocator;

struct _GumMipsRelocator
{
  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  GumAddress input_pc;
  cs_insn ** input_insns;
  GumMipsWriter * output;

  guint inpos;
  guint outpos;

  gboolean delay_slot_pending;
  gboolean eob;
  gboolean eoi;
};

void gum_mips_relocator_init (GumMipsRelocator * relocator,
    gconstpointer input_code, GumMipsWriter * output);
void gum_mips_relocator_reset (GumMipsRelocator * relocator,
    gconstpointer input_code, GumMipsWriter * output);
void gum_mips_relocator_free (GumMipsRelocator * relocator);

guint gum_mips_relocator_read_one (GumMipsRelocator * self,
    const cs_insn ** instruction);

cs_insn * gum_mips_relocator_peek_next_write_insn (GumMipsRelocator * self);
gpointer gum_mips_relocator_peek_next_write_source (GumMipsRelocator * self);
void gum_mips_relocator_skip_one (GumMipsRelocator * self);
gboolean gum_mips_relocator_write_one (GumMipsRelocator * self);
void gum_mips_relocator_write_all (GumMipsRelocator * self);

gboolean gum_mips_relocator_eob (GumMipsRelocator * self);
gboolean gum_mips_relocator_eoi (GumMipsRelocator * self);

gboolean gum_mips_relocator_can_relocate (gpointer address, guint min_bytes,
    GumRelocationScenario scenario, guint * maximum,
    mips_reg * available_scratch_reg);
guint gum_mips_relocator_relocate (gpointer from, guint min_bytes,
    gpointer to);

G_END_DECLS

#endif
