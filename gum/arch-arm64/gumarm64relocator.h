/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
  GumAddress input_pc;
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
