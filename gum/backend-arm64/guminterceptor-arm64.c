/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

#define GUM_ARM64_LOGICAL_PAGE_SIZE 4096
#define GUM_ARM64_B_MAX_DISTANCE    0x07ffffff
#define GUM_ARM64_ADRP_MAX_DISTANCE 0xfffff000

#define GUM_FRAME_OFFSET_CPU_CONTEXT 8
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + (33 * 8) + (8 * 16))

typedef struct _GumArm64FunctionContextData GumArm64FunctionContextData;

struct _GumInterceptorBackend
{
  GumArm64Writer writer;
  GumArm64Relocator relocator;

  gpointer thunks;

  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumArm64FunctionContextData
{
  guint redirect_code_size;
  arm64_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumArm64FunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static gpointer gum_make_enter_thunk (GumArm64Writer * aw);
static gpointer gum_make_leave_thunk (GumArm64Writer * aw);

static void gum_interceptor_backend_write_prolog (GumArm64Writer * aw);
static void gum_interceptor_backend_write_epilog (GumArm64Writer * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  gum_arm64_writer_init (&backend->writer, NULL);
  gum_arm64_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_arm64_relocator_free (&backend->relocator);
  gum_arm64_writer_free (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArm64FunctionContextData * data = (GumArm64FunctionContextData *)
      &ctx->backend_data;
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  if (gum_arm64_relocator_can_relocate (function_address, 16,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = 16;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (ctx->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 8)
    {
      data->redirect_code_size = 8;

      spec.near_address = GSIZE_TO_POINTER (
          GPOINTER_TO_SIZE (function_address) &
          ~((gsize) (GUM_ARM64_LOGICAL_PAGE_SIZE - 1)));
      spec.max_distance = GUM_ARM64_ADRP_MAX_DISTANCE;
      alignment = GUM_ARM64_LOGICAL_PAGE_SIZE;
    }
    else if (redirect_limit == 4)
    {
      data->redirect_code_size = 4;

      spec.near_address = function_address;
      spec.max_distance = GUM_ARM64_B_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        ctx->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
      return FALSE;
  }

  if (data->scratch_reg == ARM64_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64Relocator * ar = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumArm64FunctionContextData * data = (GumArm64FunctionContextData *)
      &ctx->backend_data;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
      GUM_ADDRESS (self->enter_thunk));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
      GUM_ADDRESS (self->leave_thunk));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
      <=, ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_relocator_reset (ar, function_address, aw);

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (ar, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < data->redirect_code_size);

  gum_arm64_relocator_write_all (ar);

  if (!ar->eoi)
  {
    GumAddress resume_at;

    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
    gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, resume_at);
    gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
  }

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64FunctionContextData * data = (GumArm64FunctionContextData *)
      &ctx->backend_data;
  GumAddress on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_arm64_writer_reset (aw, ctx->function_address);
  switch (data->redirect_code_size)
  {
    case 4:
      gum_arm64_writer_put_b_imm (aw, on_enter);
      break;
    case 8:
      gum_arm64_writer_put_adrp_reg_address (aw, ARM64_REG_X16, on_enter);
      gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
      break;
    case 16:
      gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16, on_enter);
      gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
      break;
    default:
      g_assert_not_reached ();
  }
  gum_arm64_writer_flush (aw);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx)
{
  gum_memcpy (ctx->function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

void
_gum_interceptor_backend_commit_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  gum_clear_cache (ctx->trampoline_slice->data, ctx->trampoline_slice->size);
  gum_clear_cache (ctx->function_address, ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  return gum_arm64_reader_try_get_relative_jump_target (address);
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

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumArm64Writer * aw = &self->writer;
  gsize page_size, size_in_pages, size_in_bytes;

  page_size = gum_query_page_size ();

  size_in_pages = 1;
  size_in_bytes = size_in_pages * page_size;

  self->thunks = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  gum_arm64_writer_reset (aw, self->thunks);

  self->enter_thunk = gum_make_enter_thunk (aw);
  self->leave_thunk = gum_make_leave_thunk (aw);

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw), <=, size_in_bytes);

  gum_mprotect (self->thunks, size_in_bytes, GUM_PAGE_RX);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_free_pages (self->thunks);
}

static gpointer
gum_make_enter_thunk (GumArm64Writer * aw)
{
  gpointer thunk;

  thunk = gum_arm64_writer_cur (aw);

  gum_interceptor_backend_write_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X3, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_begin_invocation),
      4,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X3);

  gum_interceptor_backend_write_epilog (aw);

  return thunk;
}

static gpointer
gum_make_leave_thunk (GumArm64Writer * aw)
{
  gpointer thunk;

  thunk = gum_arm64_writer_cur (aw);

  gum_interceptor_backend_write_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation),
      3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);

  gum_interceptor_backend_write_epilog (aw);

  return thunk;
}

static void
gum_interceptor_backend_write_prolog (GumArm64Writer * aw)
{
  /*
   * Set up our stack frame:
   *
   * [next_hop]
   * [cpu_context]
   */

  /* reserve space for next_hop */
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_SP, ARM64_REG_SP, 16);

  /* push {q0-q7}; store vector registers (for now only the clobberable ones) */
  gum_arm64_writer_put_instruction (aw, 0xadbf1fe6);
  gum_arm64_writer_put_instruction (aw, 0xadbf17e4);
  gum_arm64_writer_put_instruction (aw, 0xadbf0fe2);
  gum_arm64_writer_put_instruction (aw, 0xadbf07e0);

  /* upper part */
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X27, ARM64_REG_X28);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X25, ARM64_REG_X26);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X23, ARM64_REG_X24);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X17, ARM64_REG_X18);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X15, ARM64_REG_X16);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X13, ARM64_REG_X14);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X11, ARM64_REG_X12);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X9, ARM64_REG_X10);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X7, ARM64_REG_X8);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X5, ARM64_REG_X6);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X4);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X2);

  /* SP + X0 */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1,
      ARM64_REG_SP, (30 * 8) + (8 * 16) + 16);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);

  /* alignment padding + dummy PC */
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_SP,
      ARM64_REG_SP, 16);
}

static void
gum_interceptor_backend_write_epilog (GumArm64Writer * aw)
{
  /* alignment padding + PC */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_SP,
      ARM64_REG_SP, 16);

  /* SP + X0 */
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);

  /* the rest */
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X2);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X4);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X5, ARM64_REG_X6);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X7, ARM64_REG_X8);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X9, ARM64_REG_X10);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X11, ARM64_REG_X12);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X13, ARM64_REG_X14);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X15, ARM64_REG_X16);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X17, ARM64_REG_X18);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X23, ARM64_REG_X24);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X25, ARM64_REG_X26);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X27, ARM64_REG_X28);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);

  /* pop {q0-q7}; load vector registers (for now only the clobberable ones) */
  gum_arm64_writer_put_instruction (aw, 0xacc107e0);
  gum_arm64_writer_put_instruction (aw, 0xacc10fe2);
  gum_arm64_writer_put_instruction (aw, 0xacc117e4);
  gum_arm64_writer_put_instruction (aw, 0xacc11fe6);

  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
}
