/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

static void gum_function_context_clear_cache (FunctionContext * ctx);

static GumArm64Writer gum_function_context_writer;
static GumArm64Relocator gum_function_context_relocator;

void
_gum_function_context_init (void)
{
  gum_arm64_writer_init (&gum_function_context_writer, NULL);
  gum_arm64_relocator_init (&gum_function_context_relocator, NULL,
      &gum_function_context_writer);
}

void
_gum_function_context_deinit (void)
{
  gum_arm64_relocator_free (&gum_function_context_relocator);
  gum_arm64_writer_free (&gum_function_context_writer);
}

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  GumArm64Writer * aw = &gum_function_context_writer;
  GumArm64Relocator * ar = &gum_function_context_relocator;
  gpointer function_address;
  guint redirect_code_size, reloc_bytes;
  GumAddress resume_at;

  function_address = ctx->function_address;

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X1,
      GUM_A64REG_SP, 8);
  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X2,
      GUM_A64REG_X1, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_on_enter),
      3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, GUM_A64REG_X1,
      GUM_ARG_REGISTER, GUM_A64REG_X2);

  gum_arm64_writer_put_pop_cpu_context (aw);

  if (gum_arm64_writer_can_branch_imm (GUM_ADDRESS (function_address),
      GUM_ADDRESS (ctx->on_enter_trampoline)))
  {
    redirect_code_size = 4;
  }
  else
  {
    redirect_code_size = 16;
  }

  gum_arm64_relocator_reset (ar, function_address, aw);

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (ar, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < redirect_code_size);

  gum_arm64_relocator_write_all (ar);

  resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
  if (gum_arm64_writer_can_branch_imm (GUM_ADDRESS (gum_arm64_writer_cur (aw)),
      resume_at))
  {
    gum_arm64_writer_put_b_imm (aw, resume_at);
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X16, resume_at);
    gum_arm64_writer_put_br_reg (aw, GUM_A64REG_X16);
  }

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X1,
      GUM_A64REG_SP, 8);
  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X2,
      GUM_A64REG_X1, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_on_leave),
      3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, GUM_A64REG_X1,
      GUM_ARG_REGISTER, GUM_A64REG_X2);

  gum_arm64_writer_put_pop_cpu_context (aw);
  gum_arm64_writer_put_br_reg (aw, GUM_A64REG_LR);

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
      <=, ctx->trampoline_slice->size);
}

void
_gum_function_context_make_replace_trampoline (FunctionContext * ctx,
                                               gpointer replacement_function)
{
  gconstpointer skip_label = "gum_interceptor_replacement_skip";
  gpointer function_address;
  GumArm64Writer * aw = &gum_function_context_writer;
  GumArm64Relocator * ar = &gum_function_context_relocator;
  guint redirect_code_size, reloc_bytes;
  GumAddress resume_at;

  function_address = ctx->function_address;

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_reg_reg (aw, GUM_A64REG_X0, GUM_A64REG_X1);
  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation),
      0);
  gum_arm64_writer_put_mov_reg_reg (aw, GUM_A64REG_LR, GUM_A64REG_X0);
  gum_arm64_writer_put_pop_reg_reg (aw, GUM_A64REG_X0, GUM_A64REG_X1);
  gum_arm64_writer_put_br_reg (aw, GUM_A64REG_LR);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, GUM_A64REG_X2,
      GUM_A64REG_SP, 8);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, GUM_A64REG_X1,
      GUM_A64REG_X2, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_try_begin_invocation),
      3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, GUM_A64REG_X1,
      GUM_ARG_REGISTER, GUM_A64REG_X2);
  gum_arm64_writer_put_cbz_reg_label (aw, GUM_A64REG_W0, skip_label);

  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X0,
      GUM_ADDRESS (ctx->on_leave_trampoline));
  gum_arm64_writer_put_str_reg_reg_offset (aw, GUM_A64REG_X0,
      GUM_A64REG_SP, 8 + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_arm64_writer_put_pop_cpu_context (aw);
  gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X16,
      GUM_ADDRESS (replacement_function));
  gum_arm64_writer_put_br_reg (aw, GUM_A64REG_X16);

  gum_arm64_writer_put_label (aw, skip_label);
  gum_arm64_writer_put_pop_cpu_context (aw);

  gum_arm64_relocator_reset (ar, function_address, aw);

  if (gum_arm64_writer_can_branch_imm (GUM_ADDRESS (function_address),
      GUM_ADDRESS (ctx->on_enter_trampoline)))
  {
    redirect_code_size = 4;
  }
  else
  {
    redirect_code_size = 16;
  }

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (ar, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < redirect_code_size);

  gum_arm64_relocator_write_all (ar);

  resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
  if (gum_arm64_writer_can_branch_imm (GUM_ADDRESS (gum_arm64_writer_cur (aw)),
      resume_at))
  {
    gum_arm64_writer_put_b_imm (aw, resume_at);
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X16, resume_at);
    gum_arm64_writer_put_br_reg (aw, GUM_A64REG_X16);
  }

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
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
  GumArm64Writer * aw = &gum_function_context_writer;

  gum_arm64_writer_reset (aw, ctx->function_address);

  if (gum_arm64_writer_can_branch_imm (GUM_ADDRESS (ctx->function_address),
      GUM_ADDRESS (ctx->on_enter_trampoline)))
  {
    gum_arm64_writer_put_b_imm (aw, GUM_ADDRESS (ctx->on_enter_trampoline));
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (aw, GUM_A64REG_X16,
        GUM_ADDRESS (ctx->on_enter_trampoline));
    gum_arm64_writer_put_br_reg (aw, GUM_A64REG_X16);
  }

  gum_arm64_writer_flush (aw);

  gum_function_context_clear_cache (ctx);
}

void
_gum_function_context_deactivate_trampoline (FunctionContext * ctx)
{
  memcpy (ctx->function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
  gum_function_context_clear_cache (ctx);
}

static void
gum_function_context_clear_cache (FunctionContext * ctx)
{
  gum_clear_cache (ctx->function_address, ctx->overwritten_prologue_len);
  gum_clear_cache (ctx->trampoline_slice->data, ctx->trampoline_slice->size);
}

gpointer
_gum_interceptor_resolve_redirect (gpointer address)
{
  return NULL;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  return gum_arm64_relocator_can_relocate (function_address, 16);
}

gpointer
_gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                              guint n)
{
  if (n < 8)
  {
    return (gpointer) context->cpu_context->x[n];
  }
  else
  {
    gpointer * stack_argument = (gpointer *) context->cpu_context->sp;

    return stack_argument[n - 8];
  }
}

void
_gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context,
    guint n,
    gpointer value)
{
  if (n < 8)
  {
    context->cpu_context->x[n] = (guint64) value;
  }
  else
  {
    gpointer * stack_argument = (gpointer *) context->cpu_context->sp;

    stack_argument[n - 8] = value;
  }
}

gpointer
_gum_interceptor_invocation_get_return_value (GumInvocationContext * context)
{
  return (gpointer) context->cpu_context->x[0];
}

void
_gum_interceptor_invocation_replace_return_value (
    GumInvocationContext * context,
    gpointer value)
{
  context->cpu_context->x[0] = (guint64) value;
}

