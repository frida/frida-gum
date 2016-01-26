/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarmreader.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumthumbreader.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"

#include <string.h>
#include <unistd.h>

#define GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE        (4 + 4)
#define GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_CODE_SIZE (8 + 4)
#define GUM_INTERCEPTOR_THUMB_NEAR_REDIRECT_CODE_SIZE (6)

#define FUNCTION_CONTEXT_ADDRESS(ctx) (GSIZE_TO_POINTER ( \
    GPOINTER_TO_SIZE (ctx->function_address) & ~0x1))
#define FUNCTION_CONTEXT_ADDRESS_IS_THUMB(ctx) ( \
    (GPOINTER_TO_SIZE (ctx->function_address) & 0x1) == 0x1)

#define GUM_FRAME_OFFSET_NEXT_HOP 0
#define GUM_FRAME_OFFSET_CPU_CONTEXT \
    (GUM_FRAME_OFFSET_NEXT_HOP + sizeof (gpointer))
#define GUM_FRAME_OFFSET_TOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))

typedef struct _GumArmFunctionContextData GumArmFunctionContextData;

struct _GumInterceptorBackend
{
  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  gpointer thunks;

  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumArmFunctionContextData
{
  guint redirect_code_size;
};

G_STATIC_ASSERT (sizeof (GumArmFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static gpointer gum_make_enter_thunk (GumThumbWriter * tw);
static gpointer gum_make_leave_thunk (GumThumbWriter * tw);

static void gum_interceptor_backend_write_push_cpu_context_high_part (
    GumThumbWriter * tw);
static void gum_interceptor_backend_write_prolog (GumThumbWriter * tw);
static void gum_interceptor_backend_write_epilog (GumThumbWriter * tw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);

  gum_arm_writer_init (&backend->arm_writer, NULL);
  gum_arm_relocator_init (&backend->arm_relocator, NULL, &backend->arm_writer);

  gum_thumb_writer_init (&backend->thumb_writer, NULL);
  gum_thumb_relocator_init (&backend->thumb_relocator, NULL,
      &backend->thumb_writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_thumb_relocator_free (&backend->thumb_relocator);
  gum_thumb_writer_free (&backend->thumb_writer);

  gum_arm_relocator_free (&backend->arm_relocator);
  gum_arm_writer_free (&backend->arm_writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArmFunctionContextData * data = (GumArmFunctionContextData *)
      &ctx->backend_data;
  gpointer function_address;
  gboolean is_thumb;
  guint redirect_limit;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  if (is_thumb)
  {
    if (gum_thumb_relocator_can_relocate (function_address,
        GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_CODE_SIZE, GUM_SCENARIO_ONLINE,
        &redirect_limit))
    {
      data->redirect_code_size = GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_CODE_SIZE;
    }
    else
    {
      if (redirect_limit < GUM_INTERCEPTOR_THUMB_NEAR_REDIRECT_CODE_SIZE)
        return FALSE;

      data->redirect_code_size = GUM_INTERCEPTOR_THUMB_NEAR_REDIRECT_CODE_SIZE;
    }
  }
  else
  {
    if (gum_arm_relocator_can_relocate (function_address,
        GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE))
    {
      data->redirect_code_size = GUM_INTERCEPTOR_ARM_REDIRECT_CODE_SIZE;
    }
    else
    {
      return FALSE;
    }
  }

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (ctx->allocator);
  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  gpointer function_address;
  gboolean is_thumb;
  GumThumbWriter * tw = &self->thumb_writer;
  GumArmFunctionContextData * data = (GumArmFunctionContextData *)
      &ctx->backend_data;
  guint reloc_bytes;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_thumb_writer_reset (tw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_thumb_writer_cur (tw) + 1;

  if (is_thumb &&
      data->redirect_code_size == GUM_INTERCEPTOR_THUMB_NEAR_REDIRECT_CODE_SIZE)
  {
    GumAddressSpec caller;
    gpointer return_address;

    caller.near_address = function_address + 2 + 4;
    caller.max_distance = GUM_THUMB_B_MAX_DISTANCE;
    return_address = function_address + 6 + 1;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        ctx->allocator, &caller, return_address, ctx->on_enter_trampoline);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }
  }

  if (!is_thumb)
    gum_interceptor_backend_write_push_cpu_context_high_part (tw);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R7, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      GUM_ADDRESS (self->enter_thunk));
  gum_thumb_writer_put_bx_reg (tw, ARM_REG_R0);

  ctx->on_leave_trampoline = gum_thumb_writer_cur (tw) + 1;

  gum_interceptor_backend_write_push_cpu_context_high_part (tw);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R7, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      GUM_ADDRESS (self->leave_thunk));
  gum_thumb_writer_put_bx_reg (tw, ARM_REG_R0);

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw),
      <=, ctx->trampoline_slice->size);

  if (is_thumb)
  {
    GumThumbRelocator * tr = &self->thumb_relocator;

    ctx->on_invoke_trampoline = gum_thumb_writer_cur (tw) + 1;

    gum_thumb_relocator_reset (tr, function_address, tw);

    do
    {
      reloc_bytes = gum_thumb_relocator_read_one (tr, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < data->redirect_code_size);

    gum_thumb_relocator_write_all (tr);

    if (!gum_thumb_relocator_eoi (tr))
    {
      gum_thumb_writer_put_push_regs (tw, 2, ARM_REG_R0, ARM_REG_R1);
      gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
          GUM_ADDRESS (function_address + reloc_bytes + 1));
      gum_thumb_writer_put_str_reg_reg_offset (tw, ARM_REG_R0,
          ARM_REG_SP, 4);
      gum_thumb_writer_put_pop_regs (tw, 2, ARM_REG_R0, ARM_REG_PC);
    }
  }
  else
  {
    GumArmWriter * aw = &self->arm_writer;
    GumArmRelocator * ar = &self->arm_relocator;
    guint arm_code_size;

    if (GPOINTER_TO_SIZE (gum_thumb_writer_cur (tw)) % 4 != 0)
      gum_thumb_writer_put_nop (tw);
    ctx->on_invoke_trampoline = gum_thumb_writer_cur (tw);

    gum_arm_writer_reset (aw, ctx->on_invoke_trampoline);
    gum_arm_relocator_reset (ar, function_address, aw);

    do
    {
      reloc_bytes = gum_arm_relocator_read_one (ar, NULL);
      g_assert_cmpuint (reloc_bytes, !=, 0);
    }
    while (reloc_bytes < data->redirect_code_size);

    gum_arm_relocator_write_all (ar);

    if (!gum_arm_relocator_eoi (ar))
    {
      gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
          GUM_ADDRESS (function_address + reloc_bytes));
    }

    gum_arm_writer_flush (aw);
    arm_code_size = gum_arm_writer_offset (aw);

    gum_thumb_writer_skip (tw, arm_code_size);
  }

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw),
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
  gum_code_allocator_free_deflector (ctx->allocator, ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx)
{
  gpointer function_address;
  GumArmFunctionContextData * data = (GumArmFunctionContextData *)
      &ctx->backend_data;

  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
  {
    GumThumbWriter * tw = &self->thumb_writer;

    gum_thumb_writer_reset (tw, function_address);

    gum_interceptor_backend_write_push_cpu_context_high_part (tw);

    /* jump to stage2 */
    if (ctx->trampoline_deflector != NULL)
    {
      gum_thumb_writer_put_bl_imm (tw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
          GUM_ADDRESS (ctx->on_enter_trampoline));
      gum_thumb_writer_put_bx_reg (tw, ARM_REG_R0);
    }

    gum_thumb_writer_flush (tw);
    g_assert_cmpuint (gum_thumb_writer_offset (tw),
        <=, data->redirect_code_size);
  }
  else
  {
    GumArmWriter * aw = &self->arm_writer;

    gum_arm_writer_reset (aw, function_address);

    /* jump straight to on_enter_trampoline */
    gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
        GUM_ADDRESS (ctx->on_enter_trampoline));

    gum_arm_writer_flush (aw);
    g_assert_cmpuint (gum_arm_writer_offset (aw),
        ==, data->redirect_code_size);
  }
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx)
{
  guint8 * function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  gum_memcpy (function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

void
_gum_interceptor_backend_commit_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  gum_clear_cache (ctx->trampoline_slice->data,
      ctx->trampoline_slice->size);
  gum_clear_cache (FUNCTION_CONTEXT_ADDRESS (ctx),
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  gpointer target;

  if ((GPOINTER_TO_SIZE (address) & 1) == 1)
  {
    target = gum_thumb_reader_try_get_relative_jump_target (address);
  }
  else
  {
    target = gum_arm_reader_try_get_relative_jump_target (address);
    if (target == NULL)
      target = gum_arm_reader_try_get_indirect_jump_target (address);
  }

  return target;
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
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumThumbWriter * tw = &self->thumb_writer;
  gsize page_size, size_in_pages, size_in_bytes;

  page_size = gum_query_page_size ();

  size_in_pages = 1;
  size_in_bytes = size_in_pages * page_size;

  self->thunks = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  gum_thumb_writer_reset (tw, self->thunks);

  self->enter_thunk = gum_make_enter_thunk (tw);
  self->leave_thunk = gum_make_leave_thunk (tw);

  gum_thumb_writer_flush (tw);
  g_assert_cmpuint (gum_thumb_writer_offset (tw), <=, size_in_bytes);

  gum_mprotect (self->thunks, size_in_bytes, GUM_PAGE_RX);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_free_pages (self->thunks);
}

static gpointer
gum_make_enter_thunk (GumThumbWriter * tw)
{
  gpointer thunk;

  thunk = gum_thumb_writer_cur (tw) + 1;

  gum_interceptor_backend_write_prolog (tw);

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R2, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R3, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_thumb_writer_put_call_address_with_arguments (tw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, ARM_REG_R7,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R3);

  gum_interceptor_backend_write_epilog (tw);

  return thunk;
}

static gpointer
gum_make_leave_thunk (GumThumbWriter * tw)
{
  gpointer thunk;

  thunk = gum_thumb_writer_cur (tw) + 1;

  gum_interceptor_backend_write_prolog (tw);

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R2, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_thumb_writer_put_call_address_with_arguments (tw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM_REG_R7,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2);

  gum_interceptor_backend_write_epilog (tw);

  return thunk;
}

static void
gum_interceptor_backend_write_push_cpu_context_high_part (GumThumbWriter * tw)
{
  gum_thumb_writer_put_push_regs (tw, 8 + 1,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
      ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
      ARM_REG_LR);
}

static void
gum_interceptor_backend_write_prolog (GumThumbWriter * tw)
{
  /*
   * Set up our stack frame:
   *
   * [cpu_context] <-- high part already pushed
   * [next_hop]
   */

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (tw, 2, ARM_REG_R0, ARM_REG_R1);

  /* reserve space for next_hop and for cpsr in GumCpuContext */
  gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP, 8);
}

static void
gum_interceptor_backend_write_epilog (GumThumbWriter * tw)
{
  /* restore LR */
  gum_thumb_writer_put_ldr_reg_reg_offset (tw, ARM_REG_R0, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_thumb_writer_put_mov_reg_reg (tw, ARM_REG_LR, ARM_REG_R0);

  /* replace LR with next_hop so we can pop it straight into PC */
  gum_thumb_writer_put_ldr_reg_reg_offset (tw, ARM_REG_R0, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);
  gum_thumb_writer_put_str_reg_reg_offset (tw, ARM_REG_R0, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));

  /* clear next_hop and low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_imm (tw, ARM_REG_SP, 4 + 12);
  /* restore r[0-8] and jump straight to LR */
  gum_thumb_writer_put_pop_regs (tw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
      ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
      ARM_REG_PC);
}
