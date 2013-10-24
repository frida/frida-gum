/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gummemory.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"

#include <string.h>
#include <unistd.h>

#define GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE    (4 + 4)
#define GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE  (8 + 4)

#define FUNCTION_CONTEXT_ADDRESS(ctx) (GSIZE_TO_POINTER ( \
    GPOINTER_TO_SIZE (ctx->function_address) & ~0x1))
#define FUNCTION_CONTEXT_ADDRESS_IS_THUMB(ctx) ( \
    (GPOINTER_TO_SIZE (ctx->function_address) & 0x1) == 0x1)

static void gum_function_context_clear_cache (FunctionContext * ctx);

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  gpointer function_address;
  gboolean is_thumb;
  GumThumbWriter tw;
  guint reloc_bytes;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);
  g_assert ((GPOINTER_TO_SIZE (function_address) & 0x2) == 0);

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_thumb_writer_init (&tw, ctx->trampoline_slice->data);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_thumb_writer_cur (&tw) + 1;

  if (!is_thumb)
  {
    /* build high part of GumCpuContext */
    gum_thumb_writer_put_push_regs (&tw, 8 + 1,
        GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
        GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
        GUM_AREG_LR);
  }

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (&tw, GUM_AREG_R1, GUM_AREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (&tw, 2, GUM_AREG_R0, GUM_AREG_R1);

  /* invoke on_enter */
  gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_mov_reg_reg (&tw, GUM_AREG_R1, GUM_AREG_SP);
  gum_thumb_writer_put_mov_reg_u8 (&tw, GUM_AREG_R2, 4 + 4 + (8 * 4));
  gum_thumb_writer_put_add_reg_reg (&tw, GUM_AREG_R2, GUM_AREG_R1);
  gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R3,
      GUM_ADDRESS (_gum_function_context_on_enter));
  gum_thumb_writer_put_blx_reg (&tw, GUM_AREG_R3);

  /* restore LR */
  gum_thumb_writer_put_ldr_reg_reg_offset (&tw, GUM_AREG_R0,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_mov_reg_reg (&tw, GUM_AREG_LR, GUM_AREG_R0);

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (&tw, GUM_AREG_SP, 8);
  /* restore r[0-8] */
  gum_thumb_writer_put_pop_regs (&tw, 8,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7);
  /* clear LR */
  gum_thumb_writer_put_add_reg_imm (&tw, GUM_AREG_SP, 4);

  /* stack is now restored, let's execute the overwritten prologue */
  if (is_thumb)
  {
    GumThumbRelocator tr;

    gum_thumb_relocator_init (&tr, function_address, &tw);

    do
    {
      reloc_bytes = gum_thumb_relocator_read_one (&tr, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);

    gum_thumb_relocator_write_all (&tr);

    gum_thumb_relocator_free (&tr);

    /* and finally, jump back to the next instruction where prologue was */
    gum_thumb_writer_put_push_regs (&tw, 2, GUM_AREG_R0, GUM_AREG_R1);
    gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R0,
        GUM_ADDRESS (function_address + reloc_bytes + 1));
    gum_thumb_writer_put_str_reg_reg_offset (&tw, GUM_AREG_R0,
        GUM_AREG_SP, 4);
    gum_thumb_writer_put_pop_regs (&tw, 2, GUM_AREG_R0, GUM_AREG_PC);
  }
  else
  {
    GumArmWriter aw;
    GumArmRelocator ar;
    guint arm_code_size;

    /* switch back to ARM mode */
    if (GPOINTER_TO_SIZE (gum_thumb_writer_cur (&tw)) % 4 != 0)
      gum_thumb_writer_put_nop (&tw);
    gum_thumb_writer_put_bx_reg (&tw, GUM_AREG_PC);
    gum_thumb_writer_put_nop (&tw);

    gum_arm_writer_init (&aw, gum_thumb_writer_cur (&tw));
    gum_arm_relocator_init (&ar, function_address, &aw);

    do
    {
      reloc_bytes = gum_arm_relocator_read_one (&ar, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);

    gum_arm_relocator_write_all (&ar);

    gum_arm_relocator_free (&ar);

    /* jump back */
    gum_arm_writer_put_ldr_reg_address (&aw, GUM_AREG_PC,
        GUM_ADDRESS (function_address + reloc_bytes));

    gum_arm_writer_flush (&aw);
    arm_code_size = gum_arm_writer_offset (&aw);
    gum_arm_writer_free (&aw);

    gum_thumb_writer_skip (&tw, arm_code_size);
  }

  gum_thumb_writer_flush (&tw);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_thumb_writer_cur (&tw) + 1;

  /* build GumCpuContext */
  gum_thumb_writer_put_push_regs (&tw, 8 + 1,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
      GUM_AREG_LR);
  gum_thumb_writer_put_add_reg_reg_imm (&tw, GUM_AREG_R1, GUM_AREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (&tw, 2, GUM_AREG_R0, GUM_AREG_R1);

  /* invoke on_leave */
  gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_mov_reg_reg (&tw, GUM_AREG_R1, GUM_AREG_SP);
  gum_thumb_writer_put_add_reg_reg_imm (&tw, GUM_AREG_R2,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R3,
      GUM_ADDRESS (_gum_function_context_on_leave));
  gum_thumb_writer_put_blx_reg (&tw, GUM_AREG_R3);

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (&tw, GUM_AREG_SP, 8);
  /* restore r[0-8] and jump straight to LR */
  gum_thumb_writer_put_pop_regs (&tw, 9,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
      GUM_AREG_PC);

  gum_thumb_writer_free (&tw);

#if defined (HAVE_DARWIN) && defined (HAVE_ARM)
  gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
      GUM_PAGE_READ | GUM_PAGE_EXECUTE);
#endif
}

void
_gum_function_context_make_replace_trampoline (FunctionContext * ctx,
                                               gpointer replacement_function)
{
  g_assert_not_reached ();
}

void
_gum_function_context_destroy_trampoline (FunctionContext * ctx)
{
#if defined (HAVE_DARWIN) && defined (HAVE_ARM)
  gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
      GUM_PAGE_READ | GUM_PAGE_WRITE);
#endif

  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_function_context_activate_trampoline (FunctionContext * ctx)
{
  gpointer function_address;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
  {
    GumThumbWriter tw;

    gum_thumb_writer_init (&tw, function_address);

    /* build high part of GumCpuContext */
    gum_thumb_writer_put_push_regs (&tw, 8 + 1,
        GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
        GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
        GUM_AREG_LR);

    /* jump to stage2 */
    gum_thumb_writer_put_ldr_reg_address (&tw, GUM_AREG_R0,
        GUM_ADDRESS (ctx->on_enter_trampoline));
    gum_thumb_writer_put_bx_reg (&tw, GUM_AREG_R0);

    gum_thumb_writer_flush (&tw);
    g_assert_cmpuint (gum_thumb_writer_offset (&tw),
        ==, GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);

    gum_thumb_writer_free (&tw);
  }
  else
  {
    GumArmWriter aw;

    gum_arm_writer_init (&aw, function_address);

    /* jump straight to on_enter_trampoline */
    gum_arm_writer_put_ldr_reg_address (&aw, GUM_AREG_PC,
        GUM_ADDRESS (ctx->on_enter_trampoline));

    gum_arm_writer_flush (&aw);
    g_assert_cmpuint (gum_arm_writer_offset (&aw),
        ==, GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);

    gum_arm_writer_free (&aw);
  }

  gum_function_context_clear_cache (ctx);
}

void
_gum_function_context_deactivate_trampoline (FunctionContext * ctx)
{
  guint8 * function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  memcpy (function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
  gum_function_context_clear_cache (ctx);
}

static void
gum_function_context_clear_cache (FunctionContext * ctx)
{
  gum_clear_cache (FUNCTION_CONTEXT_ADDRESS (ctx),
      ctx->overwritten_prologue_len);
  gum_clear_cache (ctx->trampoline_slice->data,
      ctx->trampoline_slice->size);
}

gpointer
_gum_interceptor_resolve_redirect (gpointer address)
{
  return NULL;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  return TRUE;
}

gpointer
_gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                              guint n)
{
  if (n < 4)
  {
    return (gpointer) context->cpu_context->r[n];
  }
  else
  {
    gpointer * stack_argument = (gpointer *) context->cpu_context->sp;

    return stack_argument[n - 4];
  }
}

void
_gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context,
    guint n,
    gpointer value)
{
  if (n < 4)
  {
    context->cpu_context->r[n] = (guint32) value;
  }
  else
  {
    gpointer * stack_argument = (gpointer *) context->cpu_context->sp;

    stack_argument[n - 4] = value;
  }
}

gpointer
_gum_interceptor_invocation_get_return_value (GumInvocationContext * context)
{
  return (gpointer) context->cpu_context->r[0];
}
