/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_RISCV_WRITER_H__
#define __GUM_RISCV_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>
#include <gum/gummetalarray.h>
#include <gum/gummetalhash.h>

#define GUM_RISCV_JAL_MAX_DISTANCE (1 << 20)

G_BEGIN_DECLS

typedef struct _GumRiscvWriter GumRiscvWriter;

struct _GumRiscvWriter
{
  volatile gint ref_count;
  gboolean flush_on_destroy;

  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumMetalHashTable * label_defs;
  GumMetalArray label_refs;
};

GUM_API GumRiscvWriter * gum_riscv_writer_new (gpointer code_address);
GUM_API GumRiscvWriter * gum_riscv_writer_ref (GumRiscvWriter * writer);
GUM_API void gum_riscv_writer_unref (GumRiscvWriter * writer);

GUM_API void gum_riscv_writer_init (GumRiscvWriter * writer,
    gpointer code_address);
GUM_API void gum_riscv_writer_clear (GumRiscvWriter * writer);

GUM_API void gum_riscv_writer_reset (GumRiscvWriter * writer,
    gpointer code_address);

GUM_API gpointer gum_riscv_writer_cur (GumRiscvWriter * self);
GUM_API guint gum_riscv_writer_offset (GumRiscvWriter * self);
GUM_API void gum_riscv_writer_skip (GumRiscvWriter * self, guint n_bytes);

GUM_API gboolean gum_riscv_writer_flush (GumRiscvWriter * self);

GUM_API gboolean gum_riscv_writer_put_label (GumRiscvWriter * self,
    gconstpointer id);

GUM_API void gum_riscv_writer_put_call_address_with_arguments (
    GumRiscvWriter * self, GumAddress func, guint n_args, ...);
GUM_API void gum_riscv_writer_put_call_address_with_arguments_array (
    GumRiscvWriter * self, GumAddress func, guint n_args,
    const GumArgument * args);
GUM_API void gum_riscv_writer_put_call_reg_with_arguments (GumRiscvWriter * self,
    riscv_reg reg, guint n_args, ...);
GUM_API void gum_riscv_writer_put_call_reg_with_arguments_array (
    GumRiscvWriter * self, riscv_reg reg, guint n_args, const GumArgument * args);

GUM_API gboolean gum_riscv_writer_can_branch_directly_between (GumAddress from,
    GumAddress to);
GUM_API gboolean gum_riscv_writer_put_jal_imm (GumRiscvWriter * self,
    GumAddress address);
GUM_API void gum_riscv_writer_put_jal_label (GumRiscvWriter * self,
    gconstpointer label_id);
GUM_API void gum_riscv_writer_put_jalr_reg (GumRiscvWriter * self,
    riscv_reg rd, riscv_reg rs, gint32 offset);
GUM_API void gum_riscv_writer_put_ret (GumRiscvWriter * self);

GUM_API void gum_riscv_writer_put_la_reg_address (GumRiscvWriter * self,
    riscv_reg reg, GumAddress address);
GUM_API void gum_riscv_writer_put_lui_reg_imm (GumRiscvWriter * self,
    riscv_reg reg, gint32 imm);
GUM_API void gum_riscv_writer_put_auipc_reg_imm (GumRiscvWriter * self,
    riscv_reg reg, gint32 imm);
GUM_API void gum_riscv_writer_put_slli_reg_reg_imm (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg, guint8 shamt);
GUM_API void gum_riscv_writer_put_addi_reg_reg_imm (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg, gint32 imm);
GUM_API void gum_riscv_writer_put_add_reg_reg_reg (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg1, riscv_reg src_reg2);
GUM_API void gum_riscv_writer_put_ld_reg_reg_offset (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg, gint32 offset);
GUM_API void gum_riscv_writer_put_lw_reg_reg_offset (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg, gint32 offset);
GUM_API void gum_riscv_writer_put_sd_reg_reg_offset (GumRiscvWriter * self,
    riscv_reg src_reg, riscv_reg dst_reg, gint32 offset);
GUM_API void gum_riscv_writer_put_sw_reg_reg_offset (GumRiscvWriter * self,
    riscv_reg src_reg, riscv_reg dst_reg, gint32 offset);
GUM_API void gum_riscv_writer_put_mv_reg_reg (GumRiscvWriter * self,
    riscv_reg dst_reg, riscv_reg src_reg);

GUM_API void gum_riscv_writer_put_push_reg (GumRiscvWriter * self, riscv_reg reg);
GUM_API void gum_riscv_writer_put_pop_reg (GumRiscvWriter * self, riscv_reg reg);

GUM_API void gum_riscv_writer_put_nop (GumRiscvWriter * self);

GUM_API void gum_riscv_writer_put_instruction (GumRiscvWriter * self,
    guint32 insn);
GUM_API gboolean gum_riscv_writer_put_bytes (GumRiscvWriter * self,
    const guint8 * data, guint n);

G_END_DECLS

#endif
