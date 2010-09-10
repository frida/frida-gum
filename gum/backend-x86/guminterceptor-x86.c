/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#include "guminterceptor-priv.h"

#include "gumsysinternals.h"
#include "gumx86reader.h"
#include "gumx86relocator.h"

#define GUM_INTERCEPTOR_REDIRECT_CODE_SIZE  5
#define GUM_INTERCEPTOR_GUARD_MAGIC         0x47756D21

static void gum_function_context_write_guard_enter_code (FunctionContext * ctx,
    gconstpointer skip_label, GumX86Writer * cw);
static void gum_function_context_write_guard_leave_code (FunctionContext * ctx,
    GumX86Writer * cw);

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  GumX86Writer cw;
  GumX86Relocator rl;
  guint8 zeroed_header[16] = { 0, };
  gconstpointer skip_label = "gum_interceptor_on_enter_skip";
  gconstpointer dont_increment_usage_counter_label =
      "gum_interceptor_on_enter_dont_increment_usage_counter";
  guint reloc_bytes;

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      ctx->function_address);

  gum_x86_writer_init (&cw, ctx->trampoline_slice->data);
  gum_x86_relocator_init (&rl, (guint8 *) ctx->function_address, &cw);

  /*
   * Keep a usage counter at the start of the trampoline, so we can address
   * it directly on both 32 and 64 bit
   */
  ctx->trampoline_usage_counter = (gint *) gum_x86_writer_cur (&cw);
  gum_x86_writer_put_bytes (&cw, zeroed_header, sizeof (zeroed_header));

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = (guint8 *) gum_x86_writer_cur (&cw);

  gum_x86_writer_put_pushfx (&cw);
  gum_x86_writer_put_lock_inc_imm32_ptr (&cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for xip */

  gum_function_context_write_guard_enter_code (ctx, skip_label, &cw);

  /* GumCpuContext fixup of stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XSI,
      GUM_REG_XSP, sizeof (GumCpuContext) + 2 * sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XSI);

  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XSI, GUM_REG_XSP);
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XDI, GUM_REG_XSP,
      sizeof (GumCpuContext) + sizeof (gpointer));

  gum_x86_writer_put_call_with_arguments (&cw, _gum_function_context_on_enter,
      3,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI);

  gum_x86_writer_put_test_reg_reg (&cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jz_label (&cw, dont_increment_usage_counter_label,
      GUM_UNLIKELY);
  gum_x86_writer_put_lock_inc_imm32_ptr (&cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_label (&cw, dont_increment_usage_counter_label);

  gum_function_context_write_guard_leave_code (ctx, &cw);

  gum_x86_writer_put_label (&cw, skip_label);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX); /* clear xip placeholder */
  gum_x86_writer_put_popax (&cw);
  gum_x86_writer_put_lock_dec_imm32_ptr (&cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_popfx (&cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
  gum_x86_relocator_write_all (&rl);

  if (!gum_x86_relocator_eoi (&rl))
  {
    gum_x86_writer_put_jmp (&cw,
        (guint8 *) ctx->function_address + reloc_bytes);
  }

  gum_x86_writer_put_int3 (&cw);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_x86_writer_cur (&cw);

  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for ret */

  gum_x86_writer_put_pushfx (&cw);
  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder for xip */

  gum_function_context_write_guard_enter_code (ctx, NULL, &cw);

  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XSI, GUM_REG_XSP);

  gum_x86_writer_put_call_with_arguments (&cw, _gum_function_context_on_leave,
      2,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer),
      GUM_REG_XAX);

  gum_function_context_write_guard_leave_code (ctx, &cw);

  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX); /* clear xip placeholder */
  gum_x86_writer_put_popax (&cw);
  gum_x86_writer_put_lock_dec_imm32_ptr (&cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_popfx (&cw);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  g_assert_cmpuint (gum_x86_writer_offset (&cw),
      <=, ctx->trampoline_slice->size);

  gum_x86_relocator_free (&rl);
  gum_x86_writer_free (&cw);
}

void
_gum_function_context_make_replace_trampoline (FunctionContext * ctx,
                                               gpointer replacement_address,
                                               gpointer user_data)
{
  gconstpointer skip_label = "gum_interceptor_replacement_skip";
  GumX86Writer cw;
  GumX86Relocator rl;
  guint reloc_bytes;

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      ctx->function_address);

  ctx->on_leave_trampoline = ctx->trampoline_slice->data;
  gum_x86_writer_init (&cw, ctx->on_leave_trampoline);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XDX);
  gum_x86_writer_put_call_with_arguments (&cw,
      _gum_function_context_end_invocation, 0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XSP, 2 * sizeof (gpointer),
      GUM_REG_XAX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XDX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_ret (&cw);

  ctx->on_enter_trampoline = gum_x86_writer_cur (&cw);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder */

  /* GumCpuContext fixup of stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XAX,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_XSI,
      GUM_REG_XSP, sizeof (GumCpuContext));
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XDI, GUM_REG_XSP);
  gum_x86_writer_put_call_with_arguments (&cw,
      _gum_function_context_try_begin_invocation, 4,
      GUM_ARG_POINTER, ctx->function_address,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI,
      GUM_ARG_POINTER, user_data);
  gum_x86_writer_put_test_reg_reg (&cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jz_label (&cw, skip_label, GUM_NO_HINT);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (ctx->on_leave_trampoline));
  gum_x86_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XSP, GUM_REG_XAX);
  gum_x86_writer_put_jmp (&cw, replacement_address);

  gum_x86_writer_put_label (&cw, skip_label);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XAX);
  gum_x86_writer_put_popax (&cw);

  gum_x86_relocator_init (&rl, (guint8 *) ctx->function_address, &cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
  gum_x86_relocator_write_all (&rl);

  if (!gum_x86_relocator_eoi (&rl))
  {
    gum_x86_writer_put_jmp (&cw,
        (guint8 *) ctx->function_address + reloc_bytes);
  }

  gum_x86_writer_put_int3 (&cw);

  gum_x86_writer_flush (&cw);
  g_assert_cmpuint (gum_x86_writer_offset (&cw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  gum_x86_relocator_free (&rl);
  gum_x86_writer_free (&cw);
}

void
_gum_function_context_destroy_trampoline (FunctionContext * ctx)
{
  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_function_context_activate_trampoline (FunctionContext * ctx)
{
  GumX86Writer cw;
  guint padding;

  gum_x86_writer_init (&cw, ctx->function_address);
  gum_x86_writer_put_jmp (&cw, ctx->on_enter_trampoline);
  padding = ctx->overwritten_prologue_len - gum_x86_writer_offset (&cw);
  for (; padding > 0; padding--)
    gum_x86_writer_put_nop (&cw);
  gum_x86_writer_free (&cw);
}

void
_gum_function_context_deactivate_trampoline (FunctionContext * ctx)
{
  gum_mprotect (ctx->function_address, 16, GUM_PAGE_RWX);
  memcpy (ctx->function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_resolve_redirect (gpointer address)
{
  gpointer target;

  target = gum_x86_reader_try_get_relative_jump_target (address);
  if (target == NULL)
    target = gum_x86_reader_try_get_indirect_jump_target (address);

  return target;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  return gum_x86_relocator_can_relocate (function_address,
      GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
}

static void
gum_function_context_write_guard_enter_code (FunctionContext * ctx,
                                             gconstpointer skip_label,
                                             GumX86Writer * cw)
{
#ifdef G_OS_WIN32
# if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_mov_reg_fs_u32_ptr (cw, GUM_REG_EBX,
      GUM_TEB_OFFSET_SELF);
# else
  gum_x86_writer_put_mov_reg_gs_u32_ptr (cw, GUM_REG_RBX,
      GUM_TEB_OFFSET_SELF);
# endif
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_EBP,
      GUM_REG_XBX, GUM_TEB_OFFSET_INTERCEPTOR_GUARD);

  if (skip_label != NULL)
  {
    gum_x86_writer_put_cmp_reg_i32 (cw, GUM_REG_EBP,
        GUM_INTERCEPTOR_GUARD_MAGIC);
    gum_x86_writer_put_jz_label (cw, skip_label, GUM_UNLIKELY);
  }

  gum_x86_writer_put_mov_reg_offset_ptr_u32 (cw,
      GUM_REG_XBX, GUM_TEB_OFFSET_INTERCEPTOR_GUARD,
      GUM_INTERCEPTOR_GUARD_MAGIC);
#endif
}

static void
gum_function_context_write_guard_leave_code (FunctionContext * ctx,
                                             GumX86Writer * cw)
{
#ifdef G_OS_WIN32
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XBX, GUM_TEB_OFFSET_INTERCEPTOR_GUARD,
      GUM_REG_EBP);
#endif
}
