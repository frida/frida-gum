/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_THUMB_WRITER_H__
#define __GUM_THUMB_WRITER_H__

#include "gumarm.h"

#include <gum/gumarray.h>

G_BEGIN_DECLS

typedef struct _GumThumbWriter GumThumbWriter;
typedef struct _GumThumbLabelMapping GumThumbLabelMapping;
typedef struct _GumThumbLabelRef GumThumbLabelRef;
typedef struct _GumThumbLiteralRef GumThumbLiteralRef;

struct _GumThumbWriter
{
  GumOS target_os;

  guint16 * base;
  guint16 * code;
  GumAddress pc;

  GumThumbLabelMapping * id_to_address;
  guint id_to_address_len;

  GumThumbLabelRef * label_refs;
  guint label_refs_len;

  GumThumbLiteralRef * literal_refs;
  guint literal_refs_len;
};

void gum_thumb_writer_init (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_reset (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_free (GumThumbWriter * writer);

void gum_thumb_writer_set_target_os (GumThumbWriter * self, GumOS os);

gpointer gum_thumb_writer_cur (GumThumbWriter * self);
guint gum_thumb_writer_offset (GumThumbWriter * self);
void gum_thumb_writer_skip (GumThumbWriter * self, guint n_bytes);

void gum_thumb_writer_flush (GumThumbWriter * self);

void gum_thumb_writer_put_label (GumThumbWriter * self, gconstpointer id);

void gum_thumb_writer_put_call_address_with_arguments (GumThumbWriter * self, GumAddress func, guint n_args, ...);
void gum_thumb_writer_put_call_reg_with_arguments (GumThumbWriter * self, GumArmReg reg, guint n_args, ...);

void gum_thumb_writer_put_bx_reg (GumThumbWriter * self, GumArmReg reg);
void gum_thumb_writer_put_blx_reg (GumThumbWriter * self, GumArmReg reg);
void gum_thumb_writer_put_cmp_reg_imm (GumThumbWriter * self, GumArmReg reg, guint8 imm_value);
void gum_thumb_writer_put_beq_label (GumThumbWriter * self, gconstpointer label_id);
void gum_thumb_writer_put_bne_label (GumThumbWriter * self, gconstpointer label_id);
void gum_thumb_writer_put_cbz_reg_label (GumThumbWriter * self, GumArmReg reg, gconstpointer label_id);
void gum_thumb_writer_put_cbnz_reg_label (GumThumbWriter * self, GumArmReg reg, gconstpointer label_id);

void gum_thumb_writer_put_push_regs (GumThumbWriter * self, guint n_regs, GumArmReg first_reg, ...);
void gum_thumb_writer_put_pop_regs (GumThumbWriter * self, guint n_regs, GumArmReg first_reg, ...);
void gum_thumb_writer_put_ldr_reg_address (GumThumbWriter * self, GumArmReg reg, GumAddress address);
void gum_thumb_writer_put_ldr_reg_u32 (GumThumbWriter * self, GumArmReg reg, guint32 val);
void gum_thumb_writer_put_ldr_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_ldr_reg_reg_offset (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg, guint8 src_offset);
void gum_thumb_writer_put_str_reg_reg (GumThumbWriter * self, GumArmReg src_reg, GumArmReg dst_reg);
void gum_thumb_writer_put_str_reg_reg_offset (GumThumbWriter * self, GumArmReg src_reg, GumArmReg dst_reg, guint8 dst_offset);
void gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self, GumArmReg dst_reg, guint8 imm_value);
void gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_add_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, GumArmReg right_reg);
void gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, gssize right_value);
void gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, gssize imm_value);
void gum_thumb_writer_put_sub_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg src_reg);
void gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, GumArmReg right_reg);
void gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self, GumArmReg dst_reg, GumArmReg left_reg, gssize right_value);

void gum_thumb_writer_put_nop (GumThumbWriter * self);
void gum_thumb_writer_put_bkpt_imm (GumThumbWriter * self, guint8 imm);
void gum_thumb_writer_put_breakpoint (GumThumbWriter * self);

void gum_thumb_writer_put_bytes (GumThumbWriter * self, const guint8 * data, guint n);
void gum_thumb_writer_put_instruction (GumThumbWriter * self, guint16 insn);

G_END_DECLS

#endif
