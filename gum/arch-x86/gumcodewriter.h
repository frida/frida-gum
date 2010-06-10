/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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
typedef enum _GumCpuReg       GumCpuReg;
typedef enum _GumBranchHint   GumBranchHint;

typedef struct _GumLabelMapping GumLabelMapping;
typedef struct _GumLabelRef GumLabelRef;

struct _GumCodeWriter
{
  guint8 * base;
  guint8 * code;

  GumLabelMapping * id_to_address;
  guint id_to_address_len;

  GumLabelRef * label_refs;
  guint label_refs_len;
};

enum _GumCpuReg
{
  GUM_REG_EAX = 0,
  GUM_REG_ECX,
  GUM_REG_EDX,
  GUM_REG_EBX,
  GUM_REG_ESP,
  GUM_REG_EBP,
  GUM_REG_ESI,
  GUM_REG_EDI
};

enum _GumBranchHint
{
  GUM_LIKELY,
  GUM_UNLIKELY
};

void gum_code_writer_init (GumCodeWriter * writer, gpointer code_address);
void gum_code_writer_reset (GumCodeWriter * writer, gpointer code_address);
void gum_code_writer_free (GumCodeWriter * writer);

gpointer gum_code_writer_cur (GumCodeWriter * self);
guint gum_code_writer_offset (GumCodeWriter * self);

void gum_code_writer_flush (GumCodeWriter * self);

void gum_code_writer_put_label (GumCodeWriter * self, gconstpointer id);

void gum_code_writer_put_call (GumCodeWriter * self, gconstpointer target);
void gum_code_writer_put_call_eax (GumCodeWriter * self);
void gum_code_writer_put_call_indirect (GumCodeWriter * self, gconstpointer * addr);
void gum_code_writer_put_call_near_label (GumCodeWriter * self, gconstpointer label_id);
void gum_code_writer_put_jmp (GumCodeWriter * self, gconstpointer target);
void gum_code_writer_put_jmp_short_label (GumCodeWriter * self, gconstpointer label_id);
void gum_code_writer_put_jcc_short_label (GumCodeWriter * self, guint8 opcode, gconstpointer label_id);
void gum_code_writer_put_jcc_near (GumCodeWriter * self, guint8 opcode, gconstpointer target);
void gum_code_writer_put_jmp_ecx_ptr (GumCodeWriter * self);
void gum_code_writer_put_jz (GumCodeWriter * self, gconstpointer target, GumBranchHint hint);
void gum_code_writer_put_jz_label (GumCodeWriter * self, gconstpointer label_id, GumBranchHint hint);
void gum_code_writer_put_jle (GumCodeWriter * self, gconstpointer target, GumBranchHint hint);
void gum_code_writer_put_jle_label (GumCodeWriter * self, gconstpointer label_id, GumBranchHint hint);
void gum_code_writer_put_add_eax_i32 (GumCodeWriter * self, gint32 imm_value);
void gum_code_writer_put_add_eax_u32 (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_add_esp_u32 (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_and_eax (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_shl_eax (GumCodeWriter * self, guint8 imm_value);
void gum_code_writer_put_sub_ecx (GumCodeWriter * self, gint32 imm_value);
void gum_code_writer_put_sub_ecx_eax (GumCodeWriter * self);
void gum_code_writer_put_inc_eax (GumCodeWriter * self);
void gum_code_writer_put_inc_ecx (GumCodeWriter * self);
void gum_code_writer_put_dec_ecx (GumCodeWriter * self);
void gum_code_writer_put_mov_eax (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_eax_edx (GumCodeWriter * self);
void gum_code_writer_put_mov_eax_eax_ptr (GumCodeWriter * self);
void gum_code_writer_put_mov_eax_ptr (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_eax_ptr_ecx (GumCodeWriter * self);
void gum_code_writer_put_mov_eax_offset_ptr (GumCodeWriter * self, guint8 offset, guint32 value);
void gum_code_writer_put_mov_eax_offset_ptr_ecx (GumCodeWriter * self, guint8 offset);
void gum_code_writer_put_mov_ebp (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_ebx (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_ecx (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_ecx_imm_ptr (GumCodeWriter * self, gconstpointer imm_ptr);
void gum_code_writer_put_mov_ecx_eax (GumCodeWriter * self);
void gum_code_writer_put_mov_ecx_esp (GumCodeWriter * self);
void gum_code_writer_put_mov_ecx_ptr_eax (GumCodeWriter * self);
void gum_code_writer_put_mov_ecx_esp_ptr (GumCodeWriter * self);
void gum_code_writer_put_mov_ecx_esp_offset_ptr (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_mov_eax_fs_ptr (GumCodeWriter * self, guint32 fs_offset);
void gum_code_writer_put_mov_ecx_fs_ptr (GumCodeWriter * self, guint32 fs_offset);
void gum_code_writer_put_mov_edi (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_edx (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_edx_eax (GumCodeWriter * self);
void gum_code_writer_put_mov_esi (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_esp_ptr (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_mov_esp_offset_ptr_eax (GumCodeWriter * self, guint8 offset);
void gum_code_writer_put_mov_reg_u32 (GumCodeWriter * self, GumCpuReg dst_reg, guint32 imm_value);
void gum_code_writer_put_mov_fs_ptr_eax (GumCodeWriter * self, guint32 fs_offset);
void gum_code_writer_put_mov_fs_ptr_ecx (GumCodeWriter * self, guint32 fs_offset);
void gum_code_writer_put_mov_mem_reg (GumCodeWriter * self, gpointer address, GumCpuReg reg);
void gum_code_writer_put_mov_reg_offset_ptr_reg (GumCodeWriter * self, GumCpuReg dst_reg, gint8 offset, GumCpuReg src_reg);
void gum_code_writer_put_movq_xmm0_esp_offset_ptr (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movq_eax_offset_ptr_xmm0 (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movdqu_xmm0_esp_offset_ptr (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_movdqu_eax_offset_ptr_xmm0 (GumCodeWriter * self, gint8 offset);
void gum_code_writer_put_push (GumCodeWriter * self, guint32 imm_value);
void gum_code_writer_put_push_eax (GumCodeWriter * self);
void gum_code_writer_put_push_ecx (GumCodeWriter * self);
void gum_code_writer_put_push_edx (GumCodeWriter * self);
void gum_code_writer_put_pop_eax (GumCodeWriter * self);
void gum_code_writer_put_pop_ecx (GumCodeWriter * self);
void gum_code_writer_put_pop_edx (GumCodeWriter * self);
void gum_code_writer_put_push_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_pop_reg (GumCodeWriter * self, GumCpuReg reg);
void gum_code_writer_put_push_imm_ptr (GumCodeWriter * self, gconstpointer imm_ptr);
void gum_code_writer_put_pushad (GumCodeWriter * self);
void gum_code_writer_put_popad (GumCodeWriter * self);
void gum_code_writer_put_pushfd (GumCodeWriter * self);
void gum_code_writer_put_popfd (GumCodeWriter * self);
void gum_code_writer_put_ret (GumCodeWriter * self);
void gum_code_writer_put_test_eax_eax (GumCodeWriter * self);
void gum_code_writer_put_cmp_ecx (GumCodeWriter * self, gint32 imm_value);
void gum_code_writer_put_cmp_imm_ptr_imm_u32 (GumCodeWriter * self, gconstpointer imm_ptr, guint32 imm_value);
void gum_code_writer_put_lock_xadd_ecx_eax (GumCodeWriter * self);
void gum_code_writer_put_nop (GumCodeWriter * self);
void gum_code_writer_put_int3 (GumCodeWriter * self);
void gum_code_writer_put_byte (GumCodeWriter * self, guint8 b);
void gum_code_writer_put_bytes (GumCodeWriter * self, const guint8 * data, guint n);

G_END_DECLS

#endif
