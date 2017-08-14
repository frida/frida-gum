/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_WRITER_H__
#define __GUM_ARM_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>

#define GUM_ARM_B_MAX_DISTANCE 0x01fffffc

G_BEGIN_DECLS

typedef struct _GumArmWriter GumArmWriter;
typedef struct _GumArmLiteralRef GumArmLiteralRef;

struct _GumArmWriter
{
  volatile gint ref_count;

  GumOS target_os;

  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumArmLiteralRef * literal_refs;
  guint literal_refs_len;
};

GumArmWriter * gum_arm_writer_new (gpointer code_address);
GumArmWriter * gum_arm_writer_ref (GumArmWriter * writer);
void gum_arm_writer_unref (GumArmWriter * writer);

void gum_arm_writer_init (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_clear (GumArmWriter * writer);

void gum_arm_writer_reset (GumArmWriter * writer, gpointer code_address);
void gum_arm_writer_set_target_os (GumArmWriter * self, GumOS os);

gpointer gum_arm_writer_cur (GumArmWriter * self);
guint gum_arm_writer_offset (GumArmWriter * self);
void gum_arm_writer_skip (GumArmWriter * self, guint n_bytes);

gboolean gum_arm_writer_flush (GumArmWriter * self);

gboolean gum_arm_writer_put_b_imm (GumArmWriter * self, GumAddress target);

gboolean gum_arm_writer_put_ldr_reg_address (GumArmWriter * self, arm_reg reg,
    GumAddress address);
gboolean gum_arm_writer_put_ldr_reg_u32 (GumArmWriter * self, arm_reg reg,
    guint32 val);

void gum_arm_writer_put_add_reg_reg_imm (GumArmWriter * self, arm_reg dst_reg,
    arm_reg src_reg, guint32 imm_val);
void gum_arm_writer_put_ldr_reg_reg_imm (GumArmWriter * self, arm_reg dst_reg,
    arm_reg src_reg, guint32 imm_val);

void gum_arm_writer_put_nop (GumArmWriter * self);
void gum_arm_writer_put_breakpoint (GumArmWriter * self);

void gum_arm_writer_put_instruction (GumArmWriter * self, guint32 insn);
gboolean gum_arm_writer_put_bytes (GumArmWriter * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
