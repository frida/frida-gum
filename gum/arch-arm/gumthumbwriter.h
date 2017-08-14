/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_THUMB_WRITER_H__
#define __GUM_THUMB_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>

#define GUM_THUMB_B_MAX_DISTANCE 0x00fffffe

G_BEGIN_DECLS

typedef struct _GumThumbWriter GumThumbWriter;
typedef struct _GumThumbLabelMapping GumThumbLabelMapping;
typedef struct _GumThumbLabelRef GumThumbLabelRef;
typedef struct _GumThumbLiteralRef GumThumbLiteralRef;

struct _GumThumbWriter
{
  volatile gint ref_count;

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

GumThumbWriter * gum_thumb_writer_new (gpointer code_address);
GumThumbWriter * gum_thumb_writer_ref (GumThumbWriter * writer);
void gum_thumb_writer_unref (GumThumbWriter * writer);

void gum_thumb_writer_init (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_clear (GumThumbWriter * writer);

void gum_thumb_writer_reset (GumThumbWriter * writer, gpointer code_address);
void gum_thumb_writer_set_target_os (GumThumbWriter * self, GumOS os);

gpointer gum_thumb_writer_cur (GumThumbWriter * self);
guint gum_thumb_writer_offset (GumThumbWriter * self);
void gum_thumb_writer_skip (GumThumbWriter * self, guint n_bytes);

gboolean gum_thumb_writer_flush (GumThumbWriter * self);

gboolean gum_thumb_writer_put_label (GumThumbWriter * self, gconstpointer id);

void gum_thumb_writer_put_call_address_with_arguments (GumThumbWriter * self,
    GumAddress func, guint n_args, ...);
void gum_thumb_writer_put_call_reg_with_arguments (GumThumbWriter * self,
    arm_reg reg, guint n_args, ...);

void gum_thumb_writer_put_b_imm (GumThumbWriter * self, GumAddress target);
void gum_thumb_writer_put_bx_reg (GumThumbWriter * self, arm_reg reg);
void gum_thumb_writer_put_blx_reg (GumThumbWriter * self, arm_reg reg);
void gum_thumb_writer_put_bl_imm (GumThumbWriter * self, GumAddress target);
void gum_thumb_writer_put_blx_imm (GumThumbWriter * self, GumAddress target);
void gum_thumb_writer_put_cmp_reg_imm (GumThumbWriter * self, arm_reg reg,
    guint8 imm_value);
gboolean gum_thumb_writer_put_b_label (GumThumbWriter * self,
    gconstpointer label_id);
gboolean gum_thumb_writer_put_beq_label (GumThumbWriter * self,
    gconstpointer label_id);
gboolean gum_thumb_writer_put_bne_label (GumThumbWriter * self,
    gconstpointer label_id);
gboolean gum_thumb_writer_put_b_cond_label (GumThumbWriter * self, arm_cc cc,
    gconstpointer label_id);
gboolean gum_thumb_writer_put_cbz_reg_label (GumThumbWriter * self, arm_reg reg,
    gconstpointer label_id);
gboolean gum_thumb_writer_put_cbnz_reg_label (GumThumbWriter * self,
    arm_reg reg, gconstpointer label_id);

void gum_thumb_writer_put_push_regs (GumThumbWriter * self, guint n_regs,
    arm_reg first_reg, ...);
void gum_thumb_writer_put_pop_regs (GumThumbWriter * self, guint n_regs,
    arm_reg first_reg, ...);
gboolean gum_thumb_writer_put_ldr_reg_address (GumThumbWriter * self,
    arm_reg reg, GumAddress address);
gboolean gum_thumb_writer_put_ldr_reg_u32 (GumThumbWriter * self, arm_reg reg,
    guint32 val);
void gum_thumb_writer_put_ldr_reg_reg (GumThumbWriter * self, arm_reg dst_reg,
    arm_reg src_reg);
gboolean gum_thumb_writer_put_ldr_reg_reg_offset (GumThumbWriter * self,
    arm_reg dst_reg, arm_reg src_reg, gsize src_offset);
void gum_thumb_writer_put_str_reg_reg (GumThumbWriter * self, arm_reg src_reg,
    arm_reg dst_reg);
gboolean gum_thumb_writer_put_str_reg_reg_offset (GumThumbWriter * self,
    arm_reg src_reg, arm_reg dst_reg, gsize dst_offset);
void gum_thumb_writer_put_mov_reg_reg (GumThumbWriter * self, arm_reg dst_reg,
    arm_reg src_reg);
void gum_thumb_writer_put_mov_reg_u8 (GumThumbWriter * self, arm_reg dst_reg,
    guint8 imm_value);
gboolean gum_thumb_writer_put_add_reg_imm (GumThumbWriter * self,
    arm_reg dst_reg, gssize imm_value);
void gum_thumb_writer_put_add_reg_reg (GumThumbWriter * self, arm_reg dst_reg,
    arm_reg src_reg);
void gum_thumb_writer_put_add_reg_reg_reg (GumThumbWriter * self,
    arm_reg dst_reg, arm_reg left_reg, arm_reg right_reg);
gboolean gum_thumb_writer_put_add_reg_reg_imm (GumThumbWriter * self,
    arm_reg dst_reg, arm_reg left_reg, gssize right_value);
gboolean gum_thumb_writer_put_sub_reg_imm (GumThumbWriter * self,
    arm_reg dst_reg, gssize imm_value);
void gum_thumb_writer_put_sub_reg_reg (GumThumbWriter * self, arm_reg dst_reg,
    arm_reg src_reg);
void gum_thumb_writer_put_sub_reg_reg_reg (GumThumbWriter * self,
    arm_reg dst_reg, arm_reg left_reg, arm_reg right_reg);
gboolean gum_thumb_writer_put_sub_reg_reg_imm (GumThumbWriter * self,
    arm_reg dst_reg, arm_reg left_reg, gssize right_value);

void gum_thumb_writer_put_nop (GumThumbWriter * self);
void gum_thumb_writer_put_bkpt_imm (GumThumbWriter * self, guint8 imm);
void gum_thumb_writer_put_breakpoint (GumThumbWriter * self);

void gum_thumb_writer_put_instruction (GumThumbWriter * self, guint16 insn);
gboolean gum_thumb_writer_put_bytes (GumThumbWriter * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
