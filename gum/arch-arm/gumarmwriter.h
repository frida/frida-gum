/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_WRITER_H__
#define __GUM_ARM_WRITER_H__

#include "gumarm.h"

#include <gum/gumarray.h>

G_BEGIN_DECLS

typedef struct _GumArmWriter GumArmWriter;
typedef struct _GumArmLiteralRef GumArmLiteralRef;

struct _GumArmWriter
{
  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumArmLiteralRef * literal_refs;
  guint literal_refs_len;
};

void gum_arm_writer_init (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_reset (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_free (GumArmWriter * writer);

gpointer gum_arm_writer_cur (GumArmWriter * self);
guint gum_arm_writer_offset (GumArmWriter * self);
void gum_arm_writer_skip (GumArmWriter * self, guint n_bytes);

void gum_arm_writer_flush (GumArmWriter * self);

void gum_arm_writer_put_ldr_reg_address (GumArmWriter * self, GumArmReg reg, GumAddress address);
void gum_arm_writer_put_ldr_reg_u32 (GumArmWriter * self, GumArmReg reg, guint32 val);

void gum_arm_writer_put_nop (GumArmWriter * self);

void gum_arm_writer_put_bytes (GumArmWriter * self, const guint8 * data, guint n);

G_END_DECLS

#endif
