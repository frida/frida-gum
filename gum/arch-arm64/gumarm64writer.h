/*
 * Copyright (C) 2014-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
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
typedef guint GumArm64IndexMode;

struct _GumArm64Writer
{
  volatile gint ref_count;

  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GHashTable * id_to_address;
  GArray * label_refs;
  GArray * literal_refs;
  const guint32 * earliest_literal_insn;
};

enum _GumArm64IndexMode
{
  GUM_INDEX_POST_ADJUST   = 1,
  GUM_INDEX_SIGNED_OFFSET = 2,
  GUM_INDEX_PRE_ADJUST    = 3,
};

GUM_API GumArm64Writer * gum_arm64_writer_new (gpointer code_address);
GUM_API GumArm64Writer * gum_arm64_writer_ref (GumArm64Writer * writer);
GUM_API void gum_arm64_writer_unref (GumArm64Writer * writer);

GUM_API void gum_arm64_writer_init (GumArm64Writer * writer,
    gpointer code_address);
GUM_API void gum_arm64_writer_clear (GumArm64Writer * writer);

GUM_API void gum_arm64_writer_reset (GumArm64Writer * writer,
    gpointer code_address);

GUM_API gpointer gum_arm64_writer_cur (GumArm64Writer * self);
GUM_API guint gum_arm64_writer_offset (GumArm64Writer * self);
GUM_API void gum_arm64_writer_skip (GumArm64Writer * self, guint n_bytes);

GUM_API gboolean gum_arm64_writer_flush (GumArm64Writer * self);

GUM_API gboolean gum_arm64_writer_put_label (GumArm64Writer * self,
    gconstpointer id);

GUM_API void gum_arm64_writer_put_call_address_with_arguments (
    GumArm64Writer * self, GumAddress func, guint n_args, ...);
GUM_API void gum_arm64_writer_put_call_address_with_arguments_array (
    GumArm64Writer * self, GumAddress func, guint n_args,
    const GumArgument * args);
GUM_API void gum_arm64_writer_put_call_reg_with_arguments (
    GumArm64Writer * self, arm64_reg reg, guint n_args, ...);
GUM_API void gum_arm64_writer_put_call_reg_with_arguments_array (
    GumArm64Writer * self, arm64_reg reg, guint n_args,
    const GumArgument * args);

GUM_API gboolean gum_arm64_writer_put_branch_address (GumArm64Writer * self,
    GumAddress address);

GUM_API gboolean gum_arm64_writer_can_branch_directly_between (GumAddress from,
    GumAddress to);
GUM_API gboolean gum_arm64_writer_put_b_imm (GumArm64Writer * self,
    GumAddress address);
GUM_API void gum_arm64_writer_put_b_label (GumArm64Writer * self,
    gconstpointer label_id);
GUM_API void gum_arm64_writer_put_b_cond_label (GumArm64Writer * self,
    arm64_cc cc, gconstpointer label_id);
GUM_API gboolean gum_arm64_writer_put_bl_imm (GumArm64Writer * self,
    GumAddress address);
GUM_API void gum_arm64_writer_put_bl_label (GumArm64Writer * self,
    gconstpointer label_id);
GUM_API gboolean gum_arm64_writer_put_br_reg (GumArm64Writer * self,
    arm64_reg reg);
GUM_API gboolean gum_arm64_writer_put_blr_reg (GumArm64Writer * self,
    arm64_reg reg);
GUM_API void gum_arm64_writer_put_ret (GumArm64Writer * self);
GUM_API void gum_arm64_writer_put_cbz_reg_label (GumArm64Writer * self,
    arm64_reg reg, gconstpointer label_id);
GUM_API void gum_arm64_writer_put_cbnz_reg_label (GumArm64Writer * self,
    arm64_reg reg, gconstpointer label_id);
GUM_API void gum_arm64_writer_put_tbz_reg_imm_label (GumArm64Writer * self,
    arm64_reg reg, guint bit, gconstpointer label_id);
GUM_API void gum_arm64_writer_put_tbnz_reg_imm_label (GumArm64Writer * self,
    arm64_reg reg, guint bit, gconstpointer label_id);

GUM_API gboolean gum_arm64_writer_put_push_reg_reg (GumArm64Writer * self,
    arm64_reg reg_a, arm64_reg reg_b);
GUM_API gboolean gum_arm64_writer_put_pop_reg_reg (GumArm64Writer * self,
    arm64_reg reg_a, arm64_reg reg_b);
GUM_API void gum_arm64_writer_put_push_all_x_registers (GumArm64Writer * self);
GUM_API void gum_arm64_writer_put_pop_all_x_registers (GumArm64Writer * self);
GUM_API void gum_arm64_writer_put_push_all_q_registers (GumArm64Writer * self);
GUM_API void gum_arm64_writer_put_pop_all_q_registers (GumArm64Writer * self);

GUM_API gboolean gum_arm64_writer_put_ldr_reg_address (GumArm64Writer * self,
    arm64_reg reg, GumAddress address);
GUM_API gboolean gum_arm64_writer_put_ldr_reg_u64 (GumArm64Writer * self,
    arm64_reg reg, guint64 val);
GUM_API guint gum_arm64_writer_put_ldr_reg_ref (GumArm64Writer * self,
    arm64_reg reg);
GUM_API void gum_arm64_writer_put_ldr_reg_value (GumArm64Writer * self,
    guint ref, GumAddress value);
GUM_API gboolean gum_arm64_writer_put_ldr_reg_reg_offset (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg src_reg, gsize src_offset);
GUM_API gboolean gum_arm64_writer_put_ldrsw_reg_reg_offset (
    GumArm64Writer * self, arm64_reg dst_reg, arm64_reg src_reg,
    gsize src_offset);
GUM_API gboolean gum_arm64_writer_put_adrp_reg_address (GumArm64Writer * self,
    arm64_reg reg, GumAddress address);
GUM_API gboolean gum_arm64_writer_put_str_reg_reg_offset (GumArm64Writer * self,
    arm64_reg src_reg, arm64_reg dst_reg, gsize dst_offset);
GUM_API gboolean gum_arm64_writer_put_ldp_reg_reg_reg_offset (
    GumArm64Writer * self, arm64_reg reg_a, arm64_reg reg_b, arm64_reg reg_src,
    gssize src_offset, GumArm64IndexMode mode);
GUM_API gboolean gum_arm64_writer_put_stp_reg_reg_reg_offset (
    GumArm64Writer * self, arm64_reg reg_a, arm64_reg reg_b, arm64_reg reg_dst,
    gssize dst_offset, GumArm64IndexMode mode);
GUM_API gboolean gum_arm64_writer_put_mov_reg_reg (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg src_reg);
GUM_API gboolean gum_arm64_writer_put_uxtw_reg_reg (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg src_reg);
GUM_API gboolean gum_arm64_writer_put_add_reg_reg_imm (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, gsize right_value);
GUM_API gboolean gum_arm64_writer_put_add_reg_reg_reg (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, arm64_reg right_reg);
GUM_API gboolean gum_arm64_writer_put_sub_reg_reg_imm (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, gsize right_value);
GUM_API gboolean gum_arm64_writer_put_sub_reg_reg_reg (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, arm64_reg right_reg);
GUM_API gboolean gum_arm64_writer_put_and_reg_reg_imm (GumArm64Writer * self,
    arm64_reg dst_reg, arm64_reg left_reg, gsize right_value);
GUM_API gboolean gum_arm64_writer_put_tst_reg_imm (GumArm64Writer * self,
    arm64_reg reg, guint64 imm_value);
GUM_API gboolean gum_arm64_writer_put_cmp_reg_reg (GumArm64Writer * self,
    arm64_reg reg_a, arm64_reg reg_b);

GUM_API void gum_arm64_writer_put_nop (GumArm64Writer * self);
GUM_API void gum_arm64_writer_put_brk_imm (GumArm64Writer * self, guint16 imm);

GUM_API void gum_arm64_writer_put_instruction (GumArm64Writer * self,
    guint32 insn);
GUM_API gboolean gum_arm64_writer_put_bytes (GumArm64Writer * self,
    const guint8 * data, guint n);

G_END_DECLS

#endif
