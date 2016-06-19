/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gummipsreader.h"
#include "gummipsrelocator.h"
#include "gummipswriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

#define GUM_ARM64_LOGICAL_PAGE_SIZE 4096

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + (34 * 8))

typedef struct _GumMipsFunctionContextData GumMipsFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumMipsWriter writer;
  GumMipsRelocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumMipsFunctionContextData
{
  guint redirect_code_size;
  mips_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumMipsFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumMipsWriter * aw);
static void gum_emit_leave_thunk (GumMipsWriter * aw);

static void gum_emit_prolog (GumMipsWriter * aw);
static void gum_emit_epilog (GumMipsWriter * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_mips_writer_init (&backend->writer, NULL);
  gum_mips_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_mips_relocator_free (&backend->relocator);
  gum_mips_writer_free (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx,
                                            gboolean * need_deflector)
{
  GumMipsFunctionContextData * data = (GumMipsFunctionContextData *)
      &ctx->backend_data;
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  *need_deflector = FALSE;

  if (gum_mips_relocator_can_relocate (function_address, 16,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = 16;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 8)
    {
      data->redirect_code_size = 8;

      spec.near_address = function_address;
      spec.max_distance = GUM_MIPS_J_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
    {
      ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
      *need_deflector = TRUE;
    }
  }

  if (data->scratch_reg == MIPS_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumMipsWriter * cw = &self->writer;
  GumMipsRelocator * rl = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumMipsFunctionContextData * data = (GumMipsFunctionContextData *)
      &ctx->backend_data;
  gboolean need_deflector;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx, &need_deflector))
    return FALSE;

  gum_mips_writer_reset (cw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_mips_writer_cur (cw);

  if (need_deflector)
  {
    /* TODO: implement deflector behavior */
    g_assert_not_reached ();
    /*
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size - 4;
    caller.max_distance = GUM_MIPS_J_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size;

    dedicated = data->redirect_code_size == 4;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, ctx->on_enter_trampoline,
        dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_free (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }

    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
    */
  }

  /* TODO: save $t0 on the stack? */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->enter_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  ctx->on_leave_trampoline = gum_mips_writer_cur (cw);

  /* TODO: save $t0 on the stack? */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->enter_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  gum_mips_writer_flush (cw);
  g_assert_cmpuint (gum_mips_writer_offset (cw),
      <=, ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_mips_writer_cur (cw);

  gum_mips_relocator_reset (rl, function_address, cw);

  do
  {
    reloc_bytes = gum_mips_relocator_read_one (rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < data->redirect_code_size || rl->delay_slot_pending);

  gum_mips_relocator_write_all (rl);

  if (!rl->eoi)
  {
    GumAddress resume_at;

    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
    gum_mips_writer_put_la_reg_address (cw, data->scratch_reg, resume_at);
    gum_mips_writer_put_jr_reg (cw, data->scratch_reg);
  }

  gum_mips_writer_flush (cw);
  g_assert_cmpuint (gum_mips_writer_offset (cw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_free (ctx->trampoline_slice);
  gum_code_deflector_free (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumMipsWriter * cw = &self->writer;
  GumMipsFunctionContextData * data = (GumMipsFunctionContextData *)
      &ctx->backend_data;
  GumAddress on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_mips_writer_reset (cw, prologue);
  cw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->trampoline_deflector != NULL)
  {
    /* TODO: implement branch to deflector */
    g_assert_not_reached ();
    /*
    if (data->redirect_code_size == 8)
    {
      gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
      gum_arm64_writer_put_bl_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      g_assert_cmpuint (data->redirect_code_size, ==, 4);
      gum_arm64_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    */
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 8:
        gum_mips_writer_put_j_address (cw, on_enter);
        break;
      case 16:
        gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT, on_enter);
        gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_mips_writer_flush (cw);
  g_assert_cmpuint (gum_mips_writer_offset (cw), <=, data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  (void) self;

  memcpy (prologue, ctx->overwritten_prologue, ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  /* TODO: implement resolve redirect */
  g_assert_not_reached ();
  /*
  return gum_arm64_reader_try_get_relative_jump_target (address);
  */
  return NULL;
}

gpointer
_gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                              guint n)
{
  if (n < 4)
  {
    switch (n)
    {
      case 0:
        return (gpointer) context->cpu_context->a0;
      case 1:
        return (gpointer) context->cpu_context->a1;
      case 2:
        return (gpointer) context->cpu_context->a2;
      case 3:
        return (gpointer) context->cpu_context->a3;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) context->cpu_context->sp;

    return stack_argument[n - 4];
  }

  return NULL;
}

void
_gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context,
    guint n,
    gpointer value)
{
  if (n < 4)
  {
    switch (n)
    {
      case 0:
        context->cpu_context->a0 = (guint32) value;
        break;
      case 1:
        context->cpu_context->a1 = (guint32) value;
        break;
      case 2:
        context->cpu_context->a2 = (guint32) value;
        break;
      case 3:
        context->cpu_context->a3 = (guint32) value;
        break;
    }
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
  return (gpointer) context->cpu_context->v0;
}

void
_gum_interceptor_invocation_replace_return_value (
    GumInvocationContext * context,
    gpointer value)
{
  context->cpu_context->v0 = (guint32) value;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumMipsWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert_cmpuint (gum_mips_writer_offset (cw), <=, self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert_cmpuint (gum_mips_writer_offset (cw), <=, self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_free (self->leave_thunk);

  gum_code_slice_free (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumMipsWriter * cw)
{
  gum_emit_prolog (cw);

  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, ra));
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A3, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,
      GUM_ARG_REGISTER, MIPS_REG_A2,
      GUM_ARG_REGISTER, MIPS_REG_A3);

  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumMipsWriter * cw)
{
  gum_emit_prolog (cw);

  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,
      GUM_ARG_REGISTER, MIPS_REG_A2);

  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumMipsWriter * cw)
{
  /*
   * Set up our stack frame:
   *
   * [next_hop]
   * [cpu_context]
   */

  /* reserve space for next_hop */
  gum_mips_writer_put_sub_reg_reg_imm (cw, MIPS_REG_SP, MIPS_REG_SP, 4);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_K1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_K0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_S7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_A3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_V1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_mflo_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mfhi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_RA);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_FP);

  /* SP */
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      4 + (31 * 4));
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_GP);

  /* dummy PC */
  gum_mips_writer_put_sub_reg_reg_imm (cw, MIPS_REG_SP, MIPS_REG_SP, 4);
}

static void
gum_emit_epilog (GumMipsWriter * cw)
{
  /* dummy PC */
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_SP, MIPS_REG_SP, 4);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_GP);

  /* dummy SP */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_FP);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_RA);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mthi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mtlo_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V1);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A3);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S7);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K1);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_AT);
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);
}
