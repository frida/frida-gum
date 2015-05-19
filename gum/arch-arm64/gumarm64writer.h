/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM64_WRITER_H__
#define __GUM_ARM64_WRITER_H__

#include "gumarm64.h"

#include <gum/gumarray.h>

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
    GumArm64Reg reg, guint n_args, ...);

gboolean gum_arm64_writer_can_branch_imm (GumAddress from, GumAddress to);
void gum_arm64_writer_put_b_imm (GumArm64Writer * self, GumAddress address);
void gum_arm64_writer_put_bl_imm (GumArm64Writer * self, GumAddress address);
void gum_arm64_writer_put_br_reg (GumArm64Writer * self, GumArm64Reg reg);
void gum_arm64_writer_put_blr_reg (GumArm64Writer * self, GumArm64Reg reg);
void gum_arm64_writer_put_ret (GumArm64Writer * self);
void gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self, GumArm64Reg reg,
    gconstpointer label_id);
void gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
    GumArm64Reg reg, gconstpointer label_id);

void gum_arm64_writer_put_push_cpu_context (GumArm64Writer * self, GumAddress pc);
void gum_arm64_writer_put_pop_cpu_context (GumArm64Writer * self);
void gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self, GumArm64Reg reg_a, GumArm64Reg reg_b);
void gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self, GumArm64Reg reg_a, GumArm64Reg reg_b);
void gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self, GumArm64Reg reg, GumAddress address);
void gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self, GumArm64Reg reg, guint64 val);
void gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self, GumArm64Reg dst_reg, GumArm64Reg src_reg, gsize src_offset);
void gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self, GumArm64Reg src_reg, GumArm64Reg dst_reg, gsize dst_offset);
void gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self, GumArm64Reg dst_reg, GumArm64Reg src_reg);
void gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self, GumArm64Reg dst_reg, GumArm64Reg left_reg, gsize right_value);
void gum_arm64_writer_put_add_reg_reg_reg (GumArm64Writer * self, GumArm64Reg dst_reg, GumArm64Reg left_reg, GumArm64Reg right_reg);
void gum_arm64_writer_put_sub_reg_reg_imm (GumArm64Writer * self, GumArm64Reg dst_reg, GumArm64Reg left_reg, gsize right_value);

void gum_arm64_writer_put_nop (GumArm64Writer * self);
void gum_arm64_writer_put_brk_imm (GumArm64Writer * self, guint16 imm);

void gum_arm64_writer_put_bytes (GumArm64Writer * self, const guint8 * data, guint n);

G_END_DECLS

#endif
