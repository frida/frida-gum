/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_X86_WRITER_H__
#define __GUM_X86_WRITER_H__

#include <gum/gumdefs.h>

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumX86Writer GumX86Writer;
typedef guint GumCpuReg;
typedef guint GumPtrTarget;

struct _GumX86Writer
{
  volatile gint ref_count;

  GumCpuType target_cpu;
  GumAbiType target_abi;

  guint8 * base;
  guint8 * code;
  GumAddress pc;

  GHashTable * id_to_address;
  GArray * label_refs;
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

GUM_API GumX86Writer * gum_x86_writer_new (gpointer code_address);
GUM_API GumX86Writer * gum_x86_writer_ref (GumX86Writer * writer);
GUM_API void gum_x86_writer_unref (GumX86Writer * writer);

GUM_API void gum_x86_writer_init (GumX86Writer * writer,
    gpointer code_address);
GUM_API void gum_x86_writer_clear (GumX86Writer * writer);

GUM_API void gum_x86_writer_reset (GumX86Writer * writer,
    gpointer code_address);
GUM_API void gum_x86_writer_set_target_cpu (GumX86Writer * self,
    GumCpuType cpu_type);
GUM_API void gum_x86_writer_set_target_abi (GumX86Writer * self,
    GumAbiType abi_type);

GUM_API gpointer gum_x86_writer_cur (GumX86Writer * self);
GUM_API guint gum_x86_writer_offset (GumX86Writer * self);

GUM_API gboolean gum_x86_writer_flush (GumX86Writer * self);

GUM_API GumCpuReg gum_x86_writer_get_cpu_register_for_nth_argument (
    GumX86Writer * self, guint n);

GUM_API gboolean gum_x86_writer_put_label (GumX86Writer * self,
    gconstpointer id);

GUM_API gboolean gum_x86_writer_can_branch_directly_between (GumAddress from,
    GumAddress to);
GUM_API gboolean gum_x86_writer_put_call_address_with_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumAddress func,
    guint n_args, ...);
GUM_API gboolean gum_x86_writer_put_call_address_with_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumAddress func,
    guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_address_with_aligned_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumAddress func,
    guint n_args, ...);
GUM_API gboolean gum_x86_writer_put_call_address_with_aligned_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumAddress func,
    guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_reg_with_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    guint n_args, ...);
GUM_API gboolean gum_x86_writer_put_call_reg_with_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_reg_with_aligned_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    guint n_args, ...);
GUM_API gboolean gum_x86_writer_put_call_reg_with_aligned_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_reg_offset_ptr_with_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    gssize offset, guint n_args, ...);
GUM_API gboolean gum_x86_writer_put_call_reg_offset_ptr_with_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    gssize offset, guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    gssize offset, guint n_args, ...);
GUM_API gboolean
    gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments_array (
    GumX86Writer * self, GumCallingConvention conv, GumCpuReg reg,
    gssize offset, guint n_args, const GumArgument * args);
GUM_API gboolean gum_x86_writer_put_call_address (GumX86Writer * self,
    GumAddress address);
GUM_API gboolean gum_x86_writer_put_call_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_call_reg_offset_ptr (GumX86Writer * self,
    GumCpuReg reg, gssize offset);
GUM_API gboolean gum_x86_writer_put_call_indirect (GumX86Writer * self,
    GumAddress addr);
GUM_API gboolean gum_x86_writer_put_call_indirect_label (GumX86Writer * self,
    gconstpointer label_id);
GUM_API void gum_x86_writer_put_call_near_label (GumX86Writer * self,
    gconstpointer label_id);
GUM_API void gum_x86_writer_put_leave (GumX86Writer * self);
GUM_API void gum_x86_writer_put_ret (GumX86Writer * self);
GUM_API void gum_x86_writer_put_ret_imm (GumX86Writer * self,
    guint16 imm_value);
GUM_API gboolean gum_x86_writer_put_jmp_address (GumX86Writer * self,
    GumAddress address);
GUM_API void gum_x86_writer_put_jmp_short_label (GumX86Writer * self,
    gconstpointer label_id);
GUM_API void gum_x86_writer_put_jmp_near_label (GumX86Writer * self,
    gconstpointer label_id);
GUM_API gboolean gum_x86_writer_put_jmp_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_jmp_reg_ptr (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_jmp_reg_offset_ptr (GumX86Writer * self,
    GumCpuReg reg, gssize offset);
GUM_API gboolean gum_x86_writer_put_jmp_near_ptr (GumX86Writer * self,
    GumAddress address);
GUM_API gboolean gum_x86_writer_put_jcc_short (GumX86Writer * self,
    x86_insn instruction_id, gconstpointer target, GumBranchHint hint);
GUM_API gboolean gum_x86_writer_put_jcc_near (GumX86Writer * self,
    x86_insn instruction_id, gconstpointer target, GumBranchHint hint);
GUM_API void gum_x86_writer_put_jcc_short_label (GumX86Writer * self,
    x86_insn instruction_id, gconstpointer label_id, GumBranchHint hint);
GUM_API void gum_x86_writer_put_jcc_near_label (GumX86Writer * self,
    x86_insn instruction_id, gconstpointer label_id, GumBranchHint hint);

GUM_API gboolean gum_x86_writer_put_add_reg_imm (GumX86Writer * self,
    GumCpuReg reg, gssize imm_value);
GUM_API gboolean gum_x86_writer_put_add_reg_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_add_reg_near_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, GumAddress src_address);
GUM_API gboolean gum_x86_writer_put_sub_reg_imm (GumX86Writer * self,
    GumCpuReg reg, gssize imm_value);
GUM_API gboolean gum_x86_writer_put_sub_reg_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_sub_reg_near_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, GumAddress src_address);
GUM_API gboolean gum_x86_writer_put_inc_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_dec_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_inc_reg_ptr (GumX86Writer * self,
    GumPtrTarget target, GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_dec_reg_ptr (GumX86Writer * self,
    GumPtrTarget target, GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_lock_xadd_reg_ptr_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg (
    GumX86Writer * self, GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_lock_inc_imm32_ptr (GumX86Writer * self,
    gpointer target);
GUM_API gboolean gum_x86_writer_put_lock_dec_imm32_ptr (GumX86Writer * self,
    gpointer target);

GUM_API gboolean gum_x86_writer_put_and_reg_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_and_reg_u32 (GumX86Writer * self,
    GumCpuReg reg, guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_shl_reg_u8 (GumX86Writer * self,
    GumCpuReg reg, guint8 imm_value);
GUM_API gboolean gum_x86_writer_put_shr_reg_u8 (GumX86Writer * self,
    GumCpuReg reg, guint8 imm_value);
GUM_API gboolean gum_x86_writer_put_xor_reg_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);

GUM_API gboolean gum_x86_writer_put_mov_reg_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_mov_reg_u32 (GumX86Writer * self,
    GumCpuReg dst_reg, guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_mov_reg_u64 (GumX86Writer * self,
    GumCpuReg dst_reg, guint64 imm_value);
GUM_API void gum_x86_writer_put_mov_reg_address (GumX86Writer * self,
    GumCpuReg dst_reg, GumAddress address);
GUM_API void gum_x86_writer_put_mov_reg_ptr_u32 (GumX86Writer * self,
    GumCpuReg dst_reg, guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_mov_reg_offset_ptr_u32 (GumX86Writer * self,
    GumCpuReg dst_reg, gssize dst_offset, guint32 imm_value);
GUM_API void gum_x86_writer_put_mov_reg_ptr_reg (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_mov_reg_offset_ptr_reg (GumX86Writer * self,
    GumCpuReg dst_reg, gssize dst_offset, GumCpuReg src_reg);
GUM_API void gum_x86_writer_put_mov_reg_reg_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_mov_reg_reg_offset_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg, gssize src_offset);
GUM_API gboolean gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (
    GumX86Writer * self, GumCpuReg dst_reg, GumCpuReg base_reg,
    GumCpuReg index_reg, guint8 scale, gssize offset);

GUM_API gboolean gum_x86_writer_put_mov_reg_near_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, GumAddress src_address);
GUM_API gboolean gum_x86_writer_put_mov_near_ptr_reg (GumX86Writer * self,
    GumAddress dst_address, GumCpuReg src_reg);

GUM_API gboolean gum_x86_writer_put_mov_fs_u32_ptr_reg (GumX86Writer * self,
    guint32 fs_offset, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_mov_reg_fs_u32_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, guint32 fs_offset);
GUM_API gboolean gum_x86_writer_put_mov_gs_u32_ptr_reg (GumX86Writer * self,
    guint32 fs_offset, GumCpuReg src_reg);
GUM_API gboolean gum_x86_writer_put_mov_reg_gs_u32_ptr (GumX86Writer * self,
    GumCpuReg dst_reg, guint32 fs_offset);

GUM_API void gum_x86_writer_put_movq_xmm0_esp_offset_ptr (GumX86Writer * self,
    gint8 offset);
GUM_API void gum_x86_writer_put_movq_eax_offset_ptr_xmm0 (GumX86Writer * self,
    gint8 offset);
GUM_API void gum_x86_writer_put_movdqu_xmm0_esp_offset_ptr (GumX86Writer * self,
    gint8 offset);
GUM_API void gum_x86_writer_put_movdqu_eax_offset_ptr_xmm0 (GumX86Writer * self,
    gint8 offset);

GUM_API gboolean gum_x86_writer_put_lea_reg_reg_offset (GumX86Writer * self,
    GumCpuReg dst_reg, GumCpuReg src_reg, gssize src_offset);

GUM_API gboolean gum_x86_writer_put_xchg_reg_reg_ptr (GumX86Writer * self,
    GumCpuReg left_reg, GumCpuReg right_reg);

GUM_API void gum_x86_writer_put_push_u32 (GumX86Writer * self,
    guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_push_near_ptr (GumX86Writer * self,
    GumAddress address);
GUM_API gboolean gum_x86_writer_put_push_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API gboolean gum_x86_writer_put_pop_reg (GumX86Writer * self,
    GumCpuReg reg);
GUM_API void gum_x86_writer_put_push_imm_ptr (GumX86Writer * self,
    gconstpointer imm_ptr);
GUM_API void gum_x86_writer_put_pushax (GumX86Writer * self);
GUM_API void gum_x86_writer_put_popax (GumX86Writer * self);
GUM_API void gum_x86_writer_put_pushfx (GumX86Writer * self);
GUM_API void gum_x86_writer_put_popfx (GumX86Writer * self);

GUM_API gboolean gum_x86_writer_put_test_reg_reg (GumX86Writer * self,
    GumCpuReg reg_a, GumCpuReg reg_b);
GUM_API gboolean gum_x86_writer_put_test_reg_u32 (GumX86Writer * self,
    GumCpuReg reg, guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_cmp_reg_i32 (GumX86Writer * self,
    GumCpuReg reg, gint32 imm_value);
GUM_API gboolean gum_x86_writer_put_cmp_reg_offset_ptr_reg (GumX86Writer * self,
    GumCpuReg reg_a, gssize offset, GumCpuReg reg_b);
GUM_API void gum_x86_writer_put_cmp_imm_ptr_imm_u32 (GumX86Writer * self,
    gconstpointer imm_ptr, guint32 imm_value);
GUM_API gboolean gum_x86_writer_put_cmp_reg_reg (GumX86Writer * self,
    GumCpuReg reg_a, GumCpuReg reg_b);
GUM_API void gum_x86_writer_put_clc (GumX86Writer * self);
GUM_API void gum_x86_writer_put_stc (GumX86Writer * self);
GUM_API void gum_x86_writer_put_cld (GumX86Writer * self);
GUM_API void gum_x86_writer_put_std (GumX86Writer * self);

GUM_API void gum_x86_writer_put_cpuid (GumX86Writer * self);
GUM_API void gum_x86_writer_put_lfence (GumX86Writer * self);
GUM_API void gum_x86_writer_put_rdtsc (GumX86Writer * self);
GUM_API void gum_x86_writer_put_pause (GumX86Writer * self);
GUM_API void gum_x86_writer_put_nop (GumX86Writer * self);
GUM_API void gum_x86_writer_put_breakpoint (GumX86Writer * self);
GUM_API void gum_x86_writer_put_padding (GumX86Writer * self, guint n);
GUM_API void gum_x86_writer_put_nop_padding (GumX86Writer * self, guint n);

GUM_API void gum_x86_writer_put_u8 (GumX86Writer * self, guint8 value);
GUM_API void gum_x86_writer_put_s8 (GumX86Writer * self, gint8 value);
GUM_API void gum_x86_writer_put_bytes (GumX86Writer * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
