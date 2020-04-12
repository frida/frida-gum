/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ARM_WRITER_H__
#define __GUM_ARM_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>
#include <gum/gummetalarray.h>
#include <gum/gummetalhash.h>

#define GUM_ARM_B_MAX_DISTANCE 0x01fffffc

G_BEGIN_DECLS

typedef struct _GumArmWriter GumArmWriter;
typedef guint GumArmIndexMode;

enum _GumArmIndexMode
{
  GUM_INDEX_NEG = 0,
  GUM_INDEX_POS = 1,
};

struct _GumArmWriter
{
  volatile gint ref_count;

  GumOS target_os;

  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumMetalHashTable * label_defs;
  GumMetalArray label_refs;
  GumMetalArray literal_refs;
  const guint32 * earliest_literal_insn;
};

GUM_API GumArmWriter * gum_arm_writer_new (gpointer code_address);

GUM_API GumArmWriter * gum_arm_writer_ref (GumArmWriter * writer);

GUM_API void gum_arm_writer_unref (GumArmWriter * writer);

GUM_API void gum_arm_writer_init (GumArmWriter * writer, gpointer code_address);

GUM_API void gum_arm_writer_clear (GumArmWriter * writer);

GUM_API void gum_arm_writer_reset (GumArmWriter * writer,
    gpointer code_address);

GUM_API void gum_arm_writer_set_target_os (GumArmWriter * self, GumOS os);

GUM_API gpointer gum_arm_writer_cur (GumArmWriter * self);

GUM_API guint gum_arm_writer_offset (GumArmWriter * self);

GUM_API void gum_arm_writer_skip (GumArmWriter * self, guint n_bytes);

GUM_API gboolean gum_arm_writer_flush (GumArmWriter * self);

GUM_API gboolean gum_arm_writer_put_label (GumArmWriter * self,
    gconstpointer id);

GUM_API gboolean gum_arm_writer_put_b_imm (GumArmWriter * self,
    GumAddress target);

GUM_API void gum_arm_writer_put_bx_reg (GumArmWriter * self, arm_reg reg);

GUM_API void gum_arm_writer_put_b_label (GumArmWriter * self,
    gconstpointer label_id);

GUM_API gboolean gum_arm_writer_put_ldr_reg_address (GumArmWriter * self,
    arm_reg reg, GumAddress address);

GUM_API gboolean gum_arm_writer_put_ldr_reg_u32 (GumArmWriter * self,
    arm_reg reg, guint32 val);

GUM_API void gum_arm_writer_put_add_reg_reg_imm (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg, guint32 imm_val);

GUM_API void gum_arm_writer_put_ldr_reg_reg_offset (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg, GumArmIndexMode mode, gsize src_offset);

GUM_API void gum_arm_writer_put_nop (GumArmWriter * self);

GUM_API void gum_arm_writer_put_breakpoint (GumArmWriter * self);

GUM_API void gum_arm_writer_put_instruction (GumArmWriter * self, guint32 insn);

GUM_API gboolean gum_arm_writer_put_bytes (GumArmWriter * self,
    const guint8 * data, guint n);

GUM_API void gum_arm_writer_put_push_registers (GumArmWriter * self, guint cnt,
    ...);

GUM_API void gum_arm_writer_put_pop_registers (GumArmWriter * self, guint cnt,
    ...);

GUM_API void gum_arm_write_put_ldmia_registers_by_mask (GumArmWriter * self,
    arm_reg reg, gushort mask);

GUM_API void gum_arm_writer_put_mov_cpsr_to_reg (GumArmWriter * self,
    arm_reg reg);

GUM_API void gum_arm_writer_put_mov_reg_to_cpsr (GumArmWriter * self,
    arm_reg reg);

GUM_API void gum_arm_writer_put_call_address_with_arguments_array (
    GumArmWriter * self, GumAddress func, guint n_args,
    const GumArgument * args);

GUM_API void gum_arm_writer_put_mov_reg_reg (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg);

GUM_API gboolean gum_arm_writer_put_bl_imm (GumArmWriter * self,
    GumAddress target);

GUM_API gboolean gum_arm_writer_put_blr_reg (GumArmWriter * self,
    arm_reg reg);

GUM_API void gum_arm_writer_put_str_reg_reg_offset (
    GumArmWriter * self, arm_reg src_reg, arm_reg dst_reg,
    GumArmIndexMode mode, gsize dst_offset);

GUM_API void gum_arm_writer_put_strcc_reg_reg_offset (
    GumArmWriter * self, arm_cc cc, arm_reg src_reg,
    arm_reg dst_reg, GumArmIndexMode mode, gsize dst_offset);

GUM_API void gum_arm_writer_put_ret (GumArmWriter * self);

GUM_API void gum_arm_writer_put_brk_imm (GumArmWriter * self,
    guint16 imm);

GUM_API void gum_arm_writer_put_mov_reg_reg_sft (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg, arm_shifter shift,
    guint16 shift_value);

GUM_API void gum_arm_writer_put_add_reg_reg_reg_sft (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg1, arm_reg src_reg2, arm_shifter shift, guint16 shift_value);

GUM_API void gum_arm_writer_put_add_reg_reg_reg (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg1, arm_reg src_reg2);

GUM_API void gum_arm_writer_put_sub_reg_reg_reg (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg1, arm_reg src_reg2);

GUM_API void gum_arm_writer_put_cmp_reg_imm (GumArmWriter * self,
    arm_reg dst_reg, guint32 imm_val);

GUM_API void gum_arm_writer_put_bcc_label (GumArmWriter * self,
    arm_cc cc, gconstpointer label_id);

GUM_API void gum_arm_writer_put_strcc_reg_label (GumArmWriter * self,
    arm_cc cc, arm_reg reg, gconstpointer label_id);

GUM_API void gum_arm_writer_put_ldrcc_reg_label (GumArmWriter * self,
    arm_cc cc, arm_reg reg, gconstpointer label_id);

GUM_API void gum_arm_writer_put_rsbs_reg_reg (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg);

GUM_API gboolean gum_arm_writer_put_bcc_imm (GumArmWriter * self,
    arm_cc cc, GumAddress target);

GUM_API void gum_arm_writer_put_sub_reg_u16 (GumArmWriter * self,
    arm_reg dst_reg, guint16 val);

GUM_API void gum_arm_writer_put_sub_reg_reg_imm (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg, guint32 imm_val);

GUM_API void gum_arm_writer_put_and_reg_reg_imm (GumArmWriter * self,
    arm_reg dst_reg, arm_reg src_reg, guint32 imm_val);

GUM_API void gum_arm_writer_put_add_reg_u16 (GumArmWriter * self,
    arm_reg dst_reg, guint16 val);

GUM_API void gum_arm_writer_put_add_reg_u32 (GumArmWriter * self,
    arm_reg dst_reg, guint32 val);

GUM_API void gum_arm_writer_put_ldrcc_reg_reg_offset (GumArmWriter * self,
    arm_cc cc, arm_reg dst_reg, arm_reg src_reg, GumArmIndexMode mode,
    gsize src_offset);

G_END_DECLS

#endif
