/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarmreader.h"
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

static void gum_function_context_write_guard_enter_code (FunctionContext * ctx,
    gconstpointer skip_label, GumThumbWriter * tw);
static void gum_function_context_write_guard_leave_code (FunctionContext * ctx,
    GumThumbWriter * tw);

#ifdef HAVE_DARWIN
static void gum_darwin_write_ldr_r1_tls_guard_ptr (GumThumbWriter * tw);
#endif

static GumArmWriter gum_function_context_arm_writer;
static GumArmRelocator gum_function_context_arm_relocator;

static GumThumbWriter gum_function_context_thumb_writer;
static GumThumbRelocator gum_function_context_thumb_relocator;

void
_gum_function_context_init (void)
{
  gum_arm_writer_init (&gum_function_context_arm_writer, NULL);
  gum_arm_relocator_init (&gum_function_context_arm_relocator, NULL,
      &gum_function_context_arm_writer);

  gum_thumb_writer_init (&gum_function_context_thumb_writer, NULL);
  gum_thumb_relocator_init (&gum_function_context_thumb_relocator, NULL,
      &gum_function_context_thumb_writer);
}

void
_gum_function_context_deinit (void)
{
  gum_thumb_relocator_free (&gum_function_context_thumb_relocator);
  gum_thumb_writer_free (&gum_function_context_thumb_writer);

  gum_arm_relocator_free (&gum_function_context_arm_relocator);
  gum_arm_writer_free (&gum_function_context_arm_writer);
}

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  gpointer function_address;
  gboolean is_thumb;
  GumThumbWriter * tw = &gum_function_context_thumb_writer;
  gconstpointer skip_label = "gum_interceptor_on_enter_skip";
  guint reloc_bytes;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_thumb_writer_reset (tw, ctx->trampoline_slice->data);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_thumb_writer_cur (tw) + 1;

  if (!is_thumb)
  {
    /* build high part of GumCpuContext */
    gum_thumb_writer_put_push_regs (tw, 8 + 1,
        GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
        GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
        GUM_AREG_LR);
  }

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (tw, GUM_AREG_R1, GUM_AREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (tw, 2, GUM_AREG_R0, GUM_AREG_R1);

  gum_function_context_write_guard_enter_code (ctx, skip_label, tw);

  /* invoke on_enter */
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_R1, GUM_AREG_SP);
  gum_thumb_writer_put_mov_reg_u8 (tw, GUM_AREG_R2, 4 + 4 + (8 * 4));
  gum_thumb_writer_put_add_reg_reg (tw, GUM_AREG_R2, GUM_AREG_R1);
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R3,
      GUM_ADDRESS (_gum_function_context_on_enter));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R3);

  gum_function_context_write_guard_leave_code (ctx, tw);

  gum_thumb_writer_put_label (tw, skip_label);
  /* update LR to optionally trap the return (up to the C code to decide) */
  gum_thumb_writer_put_ldr_reg_reg_offset (tw, GUM_AREG_R0,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_LR, GUM_AREG_R0);

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 8);
  /* restore r[0-8] */
  gum_thumb_writer_put_pop_regs (tw, 8,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7);
  /* clear LR */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 4);

  /* stack is now restored, let's execute the overwritten prologue */
  if (is_thumb)
  {
    GumThumbRelocator * tr = &gum_function_context_thumb_relocator;

    gum_thumb_relocator_reset (tr, function_address, tw);

    do
    {
      reloc_bytes = gum_thumb_relocator_read_one (tr, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);

    gum_thumb_relocator_write_all (tr);

    /* and finally, jump back to the next instruction where prologue was */
    gum_thumb_writer_put_push_regs (tw, 2, GUM_AREG_R0, GUM_AREG_R1);
    gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
        GUM_ADDRESS (function_address + reloc_bytes + 1));
    gum_thumb_writer_put_str_reg_reg_offset (tw, GUM_AREG_R0,
        GUM_AREG_SP, 4);
    gum_thumb_writer_put_pop_regs (tw, 2, GUM_AREG_R0, GUM_AREG_PC);
  }
  else
  {
    GumArmWriter * aw = &gum_function_context_arm_writer;
    GumArmRelocator * ar = &gum_function_context_arm_relocator;
    guint arm_code_size;

    /* switch back to ARM mode */
    if (GPOINTER_TO_SIZE (gum_thumb_writer_cur (tw)) % 4 != 0)
      gum_thumb_writer_put_nop (tw);
    gum_thumb_writer_put_bx_reg (tw, GUM_AREG_PC);
    gum_thumb_writer_put_nop (tw);

    gum_arm_writer_reset (aw, gum_thumb_writer_cur (tw));
    gum_arm_relocator_reset (ar, function_address, aw);

    do
    {
      reloc_bytes = gum_arm_relocator_read_one (ar, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);

    gum_arm_relocator_write_all (ar);

    /* jump back */
    gum_arm_writer_put_ldr_reg_address (aw, GUM_AREG_PC,
        GUM_ADDRESS (function_address + reloc_bytes));

    gum_arm_writer_flush (aw);
    arm_code_size = gum_arm_writer_offset (aw);

    gum_thumb_writer_skip (tw, arm_code_size);
  }

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_thumb_writer_cur (tw) + 1;

  /* build GumCpuContext */
  gum_thumb_writer_put_push_regs (tw, 8 + 1,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
      GUM_AREG_LR);
  gum_thumb_writer_put_add_reg_reg_imm (tw, GUM_AREG_R1, GUM_AREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (tw, 2, GUM_AREG_R0, GUM_AREG_R1);

  gum_function_context_write_guard_enter_code (ctx, NULL, tw);

  /* invoke on_leave */
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_R1, GUM_AREG_SP);
  gum_thumb_writer_put_add_reg_reg_imm (tw, GUM_AREG_R2,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R3,
      GUM_ADDRESS (_gum_function_context_on_leave));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R3);

  gum_function_context_write_guard_leave_code (ctx, tw);

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 8);
  /* restore r[0-8] and jump straight to LR */
  gum_thumb_writer_put_pop_regs (tw, 9,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
      GUM_AREG_PC);

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw),
      <=, ctx->trampoline_slice->size);
}

void
_gum_function_context_make_replace_trampoline (FunctionContext * ctx,
                                               gpointer replacement_function)
{
  gconstpointer skip_label = "gum_interceptor_replacement_skip";
  gpointer function_address;
  gboolean is_thumb;
  GumThumbWriter * tw = &gum_function_context_thumb_writer;
  guint reloc_bytes;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_thumb_writer_reset (tw, ctx->trampoline_slice->data);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_thumb_writer_cur (tw) + 1;
  gum_thumb_writer_put_push_regs (tw, 1, GUM_AREG_R0);
#ifdef HAVE_QNX
  gum_thumb_writer_put_push_regs (tw, 1, GUM_AREG_R1);
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_R0, GUM_AREG_SP);
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R1,
      GUM_ADDRESS (_gum_interceptor_thread_get_orig_stack));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R1);
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_SP, GUM_AREG_R0);
  gum_thumb_writer_put_pop_regs (tw, 1, GUM_AREG_R1);
#endif
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
      GUM_ADDRESS (_gum_function_context_end_invocation));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R0);
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_LR, GUM_AREG_R0);
  gum_thumb_writer_put_pop_regs (tw, 1, GUM_AREG_R0);
  gum_thumb_writer_put_bx_reg (tw, GUM_AREG_LR);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_thumb_writer_cur (tw) + 1;

  if (!is_thumb)
  {
    /* build high part of GumCpuContext */
    gum_thumb_writer_put_push_regs (tw, 8 + 1,
        GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
        GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
        GUM_AREG_LR);
  }

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (tw, GUM_AREG_R1, GUM_AREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (tw, 2, GUM_AREG_R0, GUM_AREG_R1);

  /* check if we can invoke replacement implementation */
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_ldr_reg_reg_offset (tw, GUM_AREG_R1,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_R2, GUM_AREG_SP);
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R3,
      GUM_ADDRESS (_gum_function_context_try_begin_invocation));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R3);
  gum_thumb_writer_put_cbz_reg_label (tw, GUM_AREG_R0, skip_label);

#ifdef HAVE_QNX
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_R0, GUM_AREG_SP);
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R1,
      GUM_ADDRESS (_gum_interceptor_thread_get_side_stack));
  gum_thumb_writer_put_blx_reg (tw, GUM_AREG_R1);
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_SP, GUM_AREG_R0);
#endif
  /* update LR to trap the return */
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
      GUM_ADDRESS (ctx->on_leave_trampoline));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_LR, GUM_AREG_R0);
  /* replace LR in the GumCpuContext on stack so we can pop it into PC */
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
      GUM_ADDRESS (replacement_function));
  gum_thumb_writer_put_str_reg_reg_offset (tw, GUM_AREG_R0,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 8);
  /* restore r[0-8] and jump to replacement_function */
  gum_thumb_writer_put_pop_regs (tw, 8 + 1,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
      GUM_AREG_PC);

  /* call from within the replacement — let the call pass through */
  gum_thumb_writer_put_label (tw, skip_label);

  /* restore LR */
  gum_thumb_writer_put_ldr_reg_reg_offset (tw, GUM_AREG_R0,
      GUM_AREG_SP, G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_mov_reg_reg (tw, GUM_AREG_LR, GUM_AREG_R0);

  /* clear PC and SP from GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 8);
  /* restore r[0-8] */
  gum_thumb_writer_put_pop_regs (tw, 8,
      GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
      GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7);
  /* clear LR */
  gum_thumb_writer_put_add_reg_imm (tw, GUM_AREG_SP, 4);

  if (is_thumb)
  {
    GumThumbRelocator * tr = &gum_function_context_thumb_relocator;

    gum_thumb_relocator_reset (tr, function_address, tw);

    do
    {
      reloc_bytes = gum_thumb_relocator_read_one (tr, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);

    gum_thumb_relocator_write_all (tr);

    /* and finally, jump back to the next instruction where prologue was */
    gum_thumb_writer_put_push_regs (tw, 2, GUM_AREG_R0, GUM_AREG_R1);
    gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
        GUM_ADDRESS (function_address + reloc_bytes + 1));
    gum_thumb_writer_put_str_reg_reg_offset (tw, GUM_AREG_R0,
        GUM_AREG_SP, 4);
    gum_thumb_writer_put_pop_regs (tw, 2, GUM_AREG_R0, GUM_AREG_PC);
  }
  else
  {
    GumArmWriter * aw = &gum_function_context_arm_writer;
    GumArmRelocator * ar = &gum_function_context_arm_relocator;
    guint arm_code_size;

    /* switch back to ARM mode */
    if (GPOINTER_TO_SIZE (gum_thumb_writer_cur (tw)) % 4 != 0)
      gum_thumb_writer_put_nop (tw);
    gum_thumb_writer_put_bx_reg (tw, GUM_AREG_PC);
    gum_thumb_writer_put_nop (tw);

    gum_arm_writer_reset (aw, gum_thumb_writer_cur (tw));
    gum_arm_relocator_reset (ar, function_address, aw);

    do
    {
      reloc_bytes = gum_arm_relocator_read_one (ar, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);

    gum_arm_relocator_write_all (ar);

    /* jump back */
    gum_arm_writer_put_ldr_reg_address (aw, GUM_AREG_PC,
        GUM_ADDRESS (function_address + reloc_bytes));

    gum_arm_writer_flush (aw);
    arm_code_size = gum_arm_writer_offset (aw);

    gum_thumb_writer_skip (tw, arm_code_size);
  }

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);
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
  gpointer function_address;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
  {
    GumThumbWriter * tw = &gum_function_context_thumb_writer;

    gum_thumb_writer_reset (tw, function_address);

    /* build high part of GumCpuContext */
    gum_thumb_writer_put_push_regs (tw, 8 + 1,
        GUM_AREG_R0, GUM_AREG_R1, GUM_AREG_R2, GUM_AREG_R3,
        GUM_AREG_R4, GUM_AREG_R5, GUM_AREG_R6, GUM_AREG_R7,
        GUM_AREG_LR);

    /* jump to stage2 */
    gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
        GUM_ADDRESS (ctx->on_enter_trampoline));
    gum_thumb_writer_put_bx_reg (tw, GUM_AREG_R0);

    gum_thumb_writer_flush (tw);
    g_assert_cmpuint (gum_thumb_writer_offset (tw),
        <=, GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);
  }
  else
  {
    GumArmWriter * aw = &gum_function_context_arm_writer;

    gum_arm_writer_reset (aw, function_address);

    /* jump straight to on_enter_trampoline */
    gum_arm_writer_put_ldr_reg_address (aw, GUM_AREG_PC,
        GUM_ADDRESS (ctx->on_enter_trampoline));

    gum_arm_writer_flush (aw);
    g_assert_cmpuint (gum_arm_writer_offset (aw),
        ==, GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);
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
  gpointer target;

  /* We don't handle thumb for the moment */
  if ((GPOINTER_TO_SIZE (address) & 1) == 1)
    return NULL;

  target = gum_arm_reader_try_get_relative_jump_target (address);
  if (target == NULL)
    target = gum_arm_reader_try_get_indirect_jump_target (address);

  return target;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  if ((GPOINTER_TO_SIZE (function_address) & 1) != 0)
  {
    return gum_thumb_relocator_can_relocate (
        GSIZE_TO_POINTER (GPOINTER_TO_SIZE (function_address) & ~1),
        GUM_INTERCEPTOR_THUMB_REDIRECT_CODE_SIZE);
  }
  else
  {
    return gum_arm_relocator_can_relocate (function_address,
        GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE);
  }
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

void
_gum_interceptor_invocation_replace_return_value (
    GumInvocationContext * context,
    gpointer value)
{
  context->cpu_context->r[0] = (guint32) value;
}

static void
gum_function_context_write_guard_enter_code (FunctionContext * ctx,
                                             gconstpointer skip_label,
                                             GumThumbWriter * tw)
{
  (void) ctx;

#ifdef HAVE_DARWIN
  gum_darwin_write_ldr_r1_tls_guard_ptr (tw);

  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
      GUM_ADDRESS (ctx->interceptor));

  if (skip_label != NULL)
  {
    gum_thumb_writer_put_ldr_reg_reg (tw, GUM_AREG_R2, GUM_AREG_R1);
    gum_thumb_writer_put_sub_reg_reg (tw, GUM_AREG_R2, GUM_AREG_R0);
    gum_thumb_writer_put_cbz_reg_label (tw, GUM_AREG_R2, skip_label);
  }

  gum_thumb_writer_put_str_reg_reg (tw, GUM_AREG_R0, GUM_AREG_R1);
#endif
}

static void
gum_function_context_write_guard_leave_code (FunctionContext * ctx,
                                             GumThumbWriter * tw)
{
  (void) ctx;

#ifdef HAVE_DARWIN
  gum_darwin_write_ldr_r1_tls_guard_ptr (tw);
  gum_thumb_writer_put_ldr_reg_u32 (tw, GUM_AREG_R0, 0);
  gum_thumb_writer_put_str_reg_reg (tw, GUM_AREG_R0, GUM_AREG_R1);
#endif
}

#ifdef HAVE_DARWIN

static void
gum_darwin_write_ldr_r1_tls_guard_ptr (GumThumbWriter * tw)
{
  guint8 code[] = {
    0x1d, 0xee, 0x70, 0x1f, /* mrc 15, 0, r1, cr13, cr0, {3} */
    0x21, 0xf0, 0x03, 0x01  /* bic.w r1, r1, #3 */
  };
  gum_thumb_writer_put_bytes (tw, code, sizeof (code));
  gum_thumb_writer_put_ldr_reg_address (tw, GUM_AREG_R0,
      _gum_interceptor_guard_key * GLIB_SIZEOF_VOID_P);
  gum_thumb_writer_put_add_reg_reg (tw, GUM_AREG_R1, GUM_AREG_R0);
}

#endif
