/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM64_WRITER_H__
#define __GUM_ARM64_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>

#define GUM_ARM64_ADRP_MAX_DISTANCE 0xfffff000
#define GUM_ARM64_B_MAX_DISTANCE 0x07fffffc

G_BEGIN_DECLS

typedef struct _GumArm64Writer GumArm64Writer;
typedef struct _GumArm64LabelMapping GumArm64LabelMapping;
typedef struct _GumArm64LabelRef GumArm64LabelRef;
typedef struct _GumArm64LiteralRef GumArm64LiteralRef;

struct _GumArm64Writer
{
  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumArm64LabelMapping * id_to_address;
  guint id_to_address_len;

  GumArm64LabelRef * label_refs;
  guint label_refs_len;

  GumArm64LiteralRef * literal_refs;
  guint literal_refs_len;
};

void gum_arm64_writer_init (GumArm64Writer * writer, gpointer code_address);
void gum_arm64_writer_reset (GumArm64Writer * writer, gpointer code_address);
void gum_arm64_writer_free (GumArm64Writer * writer);

gpointer gum_arm64_writer_cur (GumArm64Writer * self);
guint gum_arm64_writer_offset (GumArm64Writer * self);
void gum_arm64_writer_skip (GumArm64Writer * self, guint n_bytes);

void gum_arm64_writer_flush (GumArm64Writer * self);

void gum_arm64_writer_put_label (GumArm64Writer * self, gconstpointer id);

void gum_arm64_writer_put_call_address_with_arguments (GumArm64Writer * self,
    GumAddress func, guint n_args, ...);
void gum_arm64_writer_put_call_reg_with_arguments (GumArm64Writer * self,
    arm64_reg reg, guint n_args, ...);

void gum_arm64_writer_put_branch_address (GumArm64Writer * self,
    GumAddress address);

gboolean gum_arm64_writer_can_branch_imm (GumAddress from, GumAddress to);
void gum_arm64_writer_put_b_imm (GumArm64Writer * self, GumAddress address);
void gum_arm64_writer_put_b_label (GumArm64Writer * self,
    gconstpointer label_id);
void gum_arm64_writer_put_b_cond_label (GumArm64Writer * self, arm64_cc cc,
    gconstpointer label_id);
void gum_arm64_writer_put_bl_imm (GumArm64Writer * self, GumAddress address);
void gum_arm64_writer_put_br_reg (GumArm64Writer * self, arm64_reg reg);
void gum_arm64_writer_put_blr_reg (GumArm64Writer * self, arm64_reg reg);
void gum_arm64_writer_put_ret (GumArm64Writer * self);
void gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self, arm64_reg reg,
    gconstpointer label_id);
void gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
    arm64_reg reg, gconstpointer label_id);
void gum_arm64_writer_put_tbz_reg_imm_label (GumArm64Writer * self,
    arm64_reg reg, guint bit, gconstpointer label_id);
void gum_arm64_writer_put_tbnz_reg_imm_label (GumArm64Writer * self,
    arm64_reg reg, guint bit, gconstpointer label_id);

void gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self, arm64_reg reg_a,
    arm64_reg reg_b);
void gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self, arm64_reg reg_a,
    arm64_reg reg_b);
void gum_arm64_writer_put_push_all_x_registers (GumArm64Writer * self);
void gum_arm64_writer_put_pop_all_x_registers (GumArm64Writer * self);
void gum_arm64_writer_put_push_all_q_registers (GumArm64Writer * self);
void gum_arm64_writer_put_pop_all_q_registers (GumArm64Writer * self);

void gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self, arm64_reg reg,
    GumAddress address);
void gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self, arm64_reg reg,
    guint64 val);
void gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg src_reg, gsize src_offset);
void gum_arm64_writer_put_adrp_reg_address (GumArm64Writer * self,
    arm64_reg reg, GumAddress address);
void gum_arm64_writer_put_ldp_reg_reg_reg_offset (GumArm64Writer * self,
    arm64_reg reg_a, arm64_reg reg_b, arm64_reg reg_src, gsize src_offset);
void gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self,
    arm64_reg src_reg, arm64_reg dst_reg, gsize dst_offset);
void gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self, arm64_reg dst_reg,
    arm64_reg src_reg);
void gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, gsize right_value);
void gum_arm64_writer_put_add_reg_reg_reg (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, arm64_reg right_reg);
void gum_arm64_writer_put_sub_reg_reg_imm (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, gsize right_value);

void gum_arm64_writer_put_nop (GumArm64Writer * self);
void gum_arm64_writer_put_brk_imm (GumArm64Writer * self, guint16 imm);

void gum_arm64_writer_put_instruction (GumArm64Writer * self, guint32 insn);
void gum_arm64_writer_put_bytes (GumArm64Writer * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
