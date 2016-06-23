/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MIPS_WRITER_H__
#define __GUM_MIPS_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>

#define GUM_MIPS_J_MAX_DISTANCE 1 << 28

G_BEGIN_DECLS

typedef struct _GumMipsWriter GumMipsWriter;
typedef struct _GumMipsLabelMapping GumMipsLabelMapping;
typedef struct _GumMipsLabelRef GumMipsLabelRef;
typedef struct _GumMipsLiteralRef GumMipsLiteralRef;

struct _GumMipsWriter
{
  guint32 * base;
  guint32 * code;
  GumAddress pc;

  GumMipsLabelMapping * id_to_address;
  guint id_to_address_len;

  GumMipsLabelRef * label_refs;
  guint label_refs_len;

  GumMipsLiteralRef * literal_refs;
  guint literal_refs_len;
};

void gum_mips_writer_init (GumMipsWriter * writer, gpointer code_address);
void gum_mips_writer_reset (GumMipsWriter * writer, gpointer code_address);
void gum_mips_writer_free (GumMipsWriter * writer);

gpointer gum_mips_writer_cur (GumMipsWriter * self);
guint gum_mips_writer_offset (GumMipsWriter * self);
void gum_mips_writer_skip (GumMipsWriter * self, guint n_bytes);

void gum_mips_writer_flush (GumMipsWriter * self);

void gum_mips_writer_put_label (GumMipsWriter * self, gconstpointer id);

void gum_mips_writer_put_call_address_with_arguments (GumMipsWriter * self,
    GumAddress func, guint n_args, ...);
void gum_mips_writer_put_call_reg_with_arguments (GumMipsWriter * self,
    mips_reg reg, guint n_args, ...);

gboolean gum_mips_writer_can_branch_directly_between (GumAddress from,
    GumAddress to);
void gum_mips_writer_put_j_address (GumMipsWriter * self, GumAddress address);
void gum_mips_writer_put_j_label (GumMipsWriter * self,
    gconstpointer label_id);
void gum_mips_writer_put_jr_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_jal_address (GumMipsWriter * self, guint32 address);
void gum_mips_writer_put_jalr_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_ret (GumMipsWriter * self);

void gum_mips_writer_put_la_reg_address (GumMipsWriter * self, mips_reg reg,
    GumAddress address);
void gum_mips_writer_put_lui_reg_imm (GumMipsWriter * self, mips_reg reg,
    guint imm);
void gum_mips_writer_put_ori_reg_reg_imm (GumMipsWriter * self,
    mips_reg rt, mips_reg rs, guint imm);
void gum_mips_writer_put_lw_reg_reg_offset (GumMipsWriter * self,
    mips_reg dst_reg, mips_reg src_reg, gsize src_offset);
void gum_mips_writer_put_sw_reg_reg_offset (GumMipsWriter * self,
    mips_reg src_reg, mips_reg dst_reg, gsize dst_offset);
void gum_mips_writer_put_mov_reg_reg (GumMipsWriter * self, mips_reg dst_reg,
    mips_reg src_reg);
void gum_mips_writer_put_addu_reg_reg_reg (GumMipsWriter * self,
    mips_reg dst_reg, mips_reg left_reg, mips_reg right_reg);
void gum_mips_writer_put_addi_reg_reg_imm (GumMipsWriter * self,
    mips_reg dest_reg, mips_reg left_reg, gint32 imm);
void gum_mips_writer_put_addi_reg_imm (GumMipsWriter * self,
    mips_reg dest_reg, gint32 imm);
void gum_mips_writer_put_sub_reg_reg_imm (GumMipsWriter * self,
    mips_reg dest_reg, mips_reg left_reg, gint32 imm);

void gum_mips_writer_put_push_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_pop_reg (GumMipsWriter * self, mips_reg reg);

void gum_mips_writer_put_mfhi_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_mflo_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_mthi_reg (GumMipsWriter * self, mips_reg reg);
void gum_mips_writer_put_mtlo_reg (GumMipsWriter * self, mips_reg reg);

void gum_mips_writer_put_nop (GumMipsWriter * self);
void gum_mips_writer_put_break (GumMipsWriter * self);

void gum_mips_writer_put_instruction (GumMipsWriter * self, guint32 insn);
void gum_mips_writer_put_bytes (GumMipsWriter * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
