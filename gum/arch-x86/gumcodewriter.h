/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUM_CODE_WRITER_H__
#define __GUM_CODE_WRITER_H__

#include "gumdefs.h"

G_BEGIN_DECLS

typedef struct _GumCodeWriter GumCodeWriter;
typedef enum _GumArgType      GumArgType;
typedef enum _GumCpuReg       GumCpuReg;
typedef enum _GumPtrTarget    GumPtrTarget;
typedef enum _GumBranchHint   GumBranchHint;

typedef struct _GumLabelMapping GumLabelMapping;
typedef struct _GumLabelRef GumLabelRef;

typedef guint64 GumAddress;

#define GUM_ADDRESS(a) ((GumAddress) a)

struct _GumCodeWriter
{
  GumCpuType target_cpu;

  guint8 * base;
  guint8 * code;

  GumLabelMapping * id_to_address;
  guint id_to_address_len;

  GumLabelRef * label_refs;
  guint label_refs_len;
};

enum _GumArgType
{
  GUM_ARG_POINTER,
  GUM_ARG_REGISTER
};

enum _GumCpuReg
{
  /* 32 bit */
  GUM_REG_EAX = 0,
  GUM_REG_ECX,
  GUM_REG_EDX,
  GUM_REG_EBX,
  GUM_REG_ESP,
  GUM_REG_EBP,
  GUM_REG_ESI,
  GUM_REG_EDI,

  GUM_REG_R8D,
  GUM_REG_R9D,
  GUM_REG_R10D,
  GUM_REG_R11D,
  GUM_REG_R12D,
  GUM_REG_R13D,
  GUM_REG_R14D,
  GUM_REG_R15D,

  GUM_REG_EIP,

  /* 64 bit */
  GUM_REG_RAX,
  GUM_REG_RCX,
  GUM_REG_RDX,
  GUM_REG_RBX,
  GUM_REG_RSP,
  GUM_REG_RBP,
  GUM_REG_RSI,
  GUM_REG_RDI,

  GUM_REG_R8,
  GUM_REG_R9,
  GUM_REG_R10,
  GUM_REG_R11,
  GUM_REG_R12,
  GUM_REG_R13,
  GUM_REG_R14,
  GUM_REG_R15,

  GUM_REG_RIP,

  /* Meta */
  GUM_REG_XAX,
  GUM_REG_XCX,
  GUM_REG_XDX,
  GUM_REG_XBX,
  GUM_REG_XSP,
  GUM_REG_XBP,
  GUM_REG_XSI,
  GUM_REG_XDI,

  GUM_REG_XIP,

  GUM_REG_NONE
};

enum _GumPtrTarget
{
  GUM_PTR_BYTE,
  GUM_PTR_DWORD,
  GUM_PTR_QWORD
};

enum _GumBranchHint
{
  GUM_NO_HINT,
  GUM_LIKELY,
  GUM_UNLIKELY
};

void gum_code_writer_init (GumCodeWriter * writer, gpointer code_address);
void gum_code_writer_reset (GumCodeWriter * writer, gpointer code_address);
void gum_code_writer_free (GumCodeWriter * writer);

void gum_code_writer_set_target_cpu (GumCodeWriter * writer, GumCpuType cpu_type);

gpointer gum_code_writer_cur (GumCodeWriter * self);
guint gum_code_writer_offset (GumCodeWriter * self);

void gum_code_writer_flush (GumCodeWriter * self);

void gum_code_writer_put_label (GumCodeWriter * self, gconstpointer id);

void gum_code_writer_put_call_with_arguments (GumCodeWriter * self, gpointer func, guint n_args, ...);
void gum_code_writer_put_call (GumCodeWriter * self, gconstpointer target);
void gum_code_writer_put_call_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_call_indirect (GumCodeWriter * self, gconstpointer * addr);
void gum_code_writer_put_call_near_label (GumCodeWriter * self, gconstpointer label_id);
void gum_code_writer_put_ret (GumCodeWriter * self);
void gum_code_writer_put_jmp (GumCodeWriter * self, gconstpointer target);
void gum_code_writer_put_jmp_short_label (GumCodeWriter * self, gconstpointer label_id);
void gum_code_writer_put_jcc_short_label (GumCodeWriter * self, guint8 opcode, gconstpointer label_id);
void gum_code_writer_put_jcc_near (GumCodeWriter * self, guint8 opcode, gconstpointer target);
void gum_code_writer_put_jmp_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_jmp_reg_ptr (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_jz (GumCodeWriter * self, gconstpointer target, GumBranchHint hint);
void gum_code_writer_put_jz_label (GumCodeWriter * self, gconstpointer label_id, GumBranchHint hint);
void gum_code_writer_put_jle (GumCodeWriter * self, gconstpointer target, GumBranchHint hint);
void gum_code_writer_put_jle_label (GumCodeWriter * self, gconstpointer label_id, GumBranchHint hint);

void gum_code_writer_put_add_reg_i8 (GumCodeWriter * self, GumCpuReg reg, gint8 imm_value);
void gum_code_writer_put_add_reg_i32 (GumCodeWriter * self, GumCpuReg reg, gint32 imm_value);
void gum_code_writer_put_add_reg_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_sub_reg_i8 (GumCodeWriter * self, GumCpuReg reg, gint8 imm_value);
void gum_code_writer_put_sub_reg_i32 (GumCodeWriter * self, GumCpuReg reg, gint32 imm_value);
void gum_code_writer_put_sub_reg_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_inc_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_dec_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_inc_reg_ptr (GumCodeWriter * self, GumPtrTarget target, GumCpuReg reg);
void gum_code_writer_put_dec_reg_ptr (GumCodeWriter * self, GumPtrTarget target, GumCpuReg reg);
void gum_code_writer_put_lock_xadd_reg_ptr_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_lock_cmpxchg_reg_ptr_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);

void gum_code_writer_put_and_reg_u32 (GumCodeWriter * self, GumCpuReg reg, guint32 imm_value);
void gum_code_writer_put_shl_reg_u8 (GumCodeWriter * self, GumCpuReg reg, guint8 imm_value);
void gum_code_writer_put_xor_reg_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);

void gum_code_writer_put_mov_reg_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_mov_reg_u32 (GumCodeWriter * self, GumCpuReg dst_reg, guint32 imm_value);
void gum_code_writer_put_mov_reg_u64 (GumCodeWriter * self, GumCpuReg dst_reg, guint64 imm_value);
void gum_code_writer_put_mov_reg_address (GumCodeWriter * self, GumCpuReg dst_reg, GumAddress address);
void gum_code_writer_put_mov_reg_ptr_u32 (GumCodeWriter * self, GumCpuReg dst_reg, guint32 imm_value);
void gum_code_writer_put_mov_reg_offset_ptr_u32 (GumCodeWriter * self, GumCpuReg dst_reg, gssize dst_offset, guint32 imm_value);
void gum_code_writer_put_mov_reg_ptr_reg (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_mov_reg_offset_ptr_reg (GumCodeWriter * self, GumCpuReg dst_reg, gssize dst_offset, GumCpuReg src_reg);
void gum_code_writer_put_mov_reg_reg_ptr (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg);
void gum_code_writer_put_mov_reg_reg_offset_ptr (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg, gssize src_offset);
void gum_code_writer_put_mov_reg_base_index_scale_offset_ptr (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg base_reg, GumCpuReg index_reg, guint8 scale, gssize offset);

void gum_code_writer_put_mov_fs_u32_ptr_reg (GumCodeWriter * self, guint32 fs_offset, GumCpuReg src_reg);
void gum_code_writer_put_mov_reg_fs_u32_ptr (GumCodeWriter * self, GumCpuReg dst_reg, guint32 fs_offset);

void gum_code_writer_put_movq_xmm0_esp_offset_ptr (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movq_eax_offset_ptr_xmm0 (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movdqu_xmm0_esp_offset_ptr (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movdqu_eax_offset_ptr_xmm0 (GumCodeWriter * self, gint8 offset);

void gum_code_writer_put_lea_reg_reg_offset (GumCodeWriter * self, GumCpuReg dst_reg, GumCpuReg src_reg, gssize src_offset);

void gum_code_writer_put_xchg_reg_reg_ptr (GumCodeWriter * self, GumCpuReg left_reg, GumCpuReg right_reg);

void gum_code_writer_put_push_u32 (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_push_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_pop_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_push_imm_ptr (GumCodeWriter * self, gconstpointer imm_ptr);
void gum_code_writer_put_pushax (GumCodeWriter * self);
void gum_code_writer_put_popax (GumCodeWriter * self);
void gum_code_writer_put_pushfx (GumCodeWriter * self);
void gum_code_writer_put_popfx (GumCodeWriter * self);

void gum_code_writer_put_test_reg_reg (GumCodeWriter * self, GumCpuReg reg_a, GumCpuReg reg_b);
void gum_code_writer_put_cmp_reg_i32 (GumCodeWriter * self, GumCpuReg reg, gint32 imm_value);
void gum_code_writer_put_cmp_imm_ptr_imm_u32 (GumCodeWriter * self, gconstpointer imm_ptr, guint32 imm_value);

void gum_code_writer_put_pause (GumCodeWriter * self);
void gum_code_writer_put_nop (GumCodeWriter * self);
void gum_code_writer_put_int3 (GumCodeWriter * self);

void gum_code_writer_put_byte (GumCodeWriter * self, guint8 b);
void gum_code_writer_put_bytes (GumCodeWriter * self, const guint8 * data, guint n);

G_END_DECLS

#endif
