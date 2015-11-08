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

typedef struct _GumFunctionContextBackendData GumFunctionContextBackendData;

struct _GumInterceptorBackend
{
  GumArm64Writer writer;
  GumArm64Relocator relocator;

  gpointer thunks;

  gpointer monitor_enter_thunk;
  gpointer monitor_leave_thunk;

  gpointer replace_enter_thunk;
  gpointer replace_leave_thunk;
};

struct _GumFunctionContextBackendData
{
  guint redirect_code_size;
  arm64_reg scratch_reg;
};

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static gpointer gum_make_monitor_enter_thunk (GumArm64Writer * aw);
static gpointer gum_make_monitor_leave_thunk (GumArm64Writer * aw);
static gpointer gum_make_replace_enter_thunk (GumArm64Writer * aw,
    gpointer replace_leave_thunk);
static gpointer gum_make_replace_leave_thunk (GumArm64Writer * aw);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

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

  self->monitor_enter_thunk = gum_make_monitor_enter_thunk (aw);
  self->monitor_leave_thunk = gum_make_monitor_leave_thunk (aw);

  self->replace_leave_thunk = gum_make_replace_leave_thunk (aw);
  self->replace_enter_thunk = gum_make_replace_enter_thunk (aw,
      self->replace_leave_thunk);

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw), <=, size_in_bytes);

  gum_mprotect (self->thunks, size_in_bytes, GUM_PAGE_RX);
}

static gpointer
gum_make_monitor_enter_thunk (GumArm64Writer * aw)
{
  gpointer thunk;

  thunk = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1,
      ARM64_REG_SP, 8);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2,
      ARM64_REG_X1, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_on_enter),
      3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);

  gum_arm64_writer_put_pop_cpu_context (aw);

  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  return thunk;
}

static gpointer
gum_make_monitor_leave_thunk (GumArm64Writer * aw)
{
  gpointer thunk;

  thunk = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1,
      ARM64_REG_SP, 8);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2,
      ARM64_REG_X1, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_on_leave),
      3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);

  gum_arm64_writer_put_pop_cpu_context (aw);
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_LR);

  return thunk;
}

static gpointer
gum_make_replace_enter_thunk (GumArm64Writer * aw,
                              gpointer replace_leave_thunk)
{
  gpointer thunk;
  gconstpointer skip_label = "gum_interceptor_replacement_skip";

  thunk = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_push_cpu_context (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2,
      ARM64_REG_SP, 8);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X1,
      ARM64_REG_X2, G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_try_begin_invocation),
      3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);
  gum_arm64_writer_put_cbz_reg_label (aw, ARM64_REG_W0, skip_label);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X0,
      GUM_ADDRESS (replace_leave_thunk));
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0,
      ARM64_REG_SP, 8 + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_arm64_writer_put_pop_cpu_context (aw);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X16,
      ARM64_REG_X17,
      G_STRUCT_OFFSET (GumFunctionContext, replacement_function));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  gum_arm64_writer_put_label (aw, skip_label);
  gum_arm64_writer_put_pop_cpu_context (aw);
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  return thunk;
}

static gpointer
gum_make_replace_leave_thunk (GumArm64Writer * aw)
{
  gpointer thunk;

  thunk = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation),
      0);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_LR, ARM64_REG_X0);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_LR);

  return thunk;
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_free_pages (self->thunks);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumFunctionContextBackendData * data = (GumFunctionContextBackendData *)
      ctx->backend_data;
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
_gum_interceptor_backend_make_monitor_trampoline (GumInterceptorBackend * self,
                                                  GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64Relocator * ar = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumFunctionContextBackendData * data = (GumFunctionContextBackendData *)
      ctx->backend_data;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16, aw->pc + (5 * 4));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
      GUM_ADDRESS (self->monitor_enter_thunk));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

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

  ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
      GUM_ADDRESS (self->monitor_leave_thunk));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

  gum_arm64_writer_flush (aw);
  g_assert_cmpuint (gum_arm64_writer_offset (aw),
      <=, ctx->trampoline_slice->size);

  return TRUE;
}

gboolean
_gum_interceptor_backend_make_replace_trampoline (GumInterceptorBackend * self,
                                                  GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64Relocator * ar = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumFunctionContextBackendData * data = (GumFunctionContextBackendData *)
      ctx->backend_data;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_arm64_writer_cur (aw);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16, aw->pc + (5 * 4));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
      GUM_ADDRESS (self->replace_enter_thunk));
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

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

  ctx->on_leave_trampoline = self->replace_leave_thunk;

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
  GumFunctionContextBackendData * data = (GumFunctionContextBackendData *)
      ctx->backend_data;
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

gboolean
_gum_interceptor_backend_can_intercept (GumInterceptorBackend * self,
                                        gpointer function_address)
{
  return TRUE;
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

