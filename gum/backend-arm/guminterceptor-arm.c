/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

#define GUM_INTERCEPTOR_ARM_FULL_REDIRECT_SIZE   (4 + 4)
#define GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE   (4)
#define GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE (8)
#define GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE (6)
#define GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE (4)

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
  GumCodeAllocator * allocator;

  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  GumCodeSlice * thunks;

  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumArmFunctionContextData
{
  guint full_redirect_size;
  guint redirect_code_size;
};

G_STATIC_ASSERT (sizeof (GumArmFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumThumbWriter * tw);
static void gum_emit_leave_thunk (GumThumbWriter * tw);

static void gum_emit_push_cpu_context_high_part (GumThumbWriter * tw);
static void gum_emit_prolog (GumThumbWriter * tw);
static void gum_emit_epilog (GumThumbWriter * tw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

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

  gum_thumb_relocator_clear (&backend->thumb_relocator);
  gum_thumb_writer_clear (&backend->thumb_writer);

  gum_arm_relocator_clear (&backend->arm_relocator);
  gum_arm_writer_clear (&backend->arm_writer);

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

  function_address = _gum_interceptor_backend_get_function_address (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  if (is_thumb)
  {
    data->full_redirect_size = GUM_INTERCEPTOR_THUMB_FULL_REDIRECT_SIZE;
    if ((GPOINTER_TO_SIZE (function_address) & 3) != 0)
      data->full_redirect_size += 2;

    if (gum_thumb_relocator_can_relocate (function_address,
        data->full_redirect_size, GUM_SCENARIO_ONLINE, &redirect_limit))
    {
      data->redirect_code_size = data->full_redirect_size;
    }
    else
    {
      if (redirect_limit >= GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE;
      else if (redirect_limit >= GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE;
      else
        return FALSE;
    }
  }
  else
  {
    data->full_redirect_size = GUM_INTERCEPTOR_ARM_FULL_REDIRECT_SIZE;

    if (gum_arm_relocator_can_relocate (function_address,
        data->full_redirect_size, &redirect_limit))
    {
      data->redirect_code_size = data->full_redirect_size;
    }
    else
    {
      if (redirect_limit >= GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE)
        data->redirect_code_size = GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE;
      else
        return FALSE;
    }
  }

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
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

  function_address = _gum_interceptor_backend_get_function_address (ctx);
  is_thumb = FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx);

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_thumb_writer_reset (tw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_thumb_writer_cur (tw) + 1;

  if (is_thumb && data->redirect_code_size != data->full_redirect_size)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size;
    caller.max_distance = GUM_THUMB_B_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size + 1;

    dedicated =
        data->redirect_code_size == GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, ctx->on_enter_trampoline,
        dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_free (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }
  }

  if (!is_thumb && data->redirect_code_size != data->full_redirect_size)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size + 4;
    caller.max_distance = GUM_ARM_B_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size;

    dedicated = TRUE;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, ctx->on_enter_trampoline,
        dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_free (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }
  }

  if (!is_thumb ||
      data->redirect_code_size != GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
  {
    gum_emit_push_cpu_context_high_part (tw);
  }

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R7, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
      GUM_ADDRESS (self->enter_thunk));

  ctx->on_leave_trampoline = gum_thumb_writer_cur (tw) + 1;

  gum_emit_push_cpu_context_high_part (tw);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R7, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
      GUM_ADDRESS (self->leave_thunk));

  gum_thumb_writer_flush (tw);
  g_assert (gum_thumb_writer_offset (tw) <= ctx->trampoline_slice->size);

  if (is_thumb)
  {
    GumThumbRelocator * tr = &self->thumb_relocator;
    GString * signature;
    gboolean is_eligible_for_lr_rewriting;

    ctx->on_invoke_trampoline = gum_thumb_writer_cur (tw) + 1;

    gum_thumb_relocator_reset (tr, function_address, tw);

    signature = g_string_sized_new (16);

    do
    {
      const cs_insn * insn;

      reloc_bytes = gum_thumb_relocator_read_one (tr, &insn);

      if (reloc_bytes != 0)
      {
        if (signature->len != 0)
          g_string_append_c (signature, ';');
        g_string_append (signature, insn->mnemonic);
      }
      else
      {
        reloc_bytes = data->redirect_code_size;
      }
    }
    while (reloc_bytes < data->redirect_code_size);

    /*
     * Try to deal with minimal thunks that determine their caller and pass
     * it along to some inner function. This is important to support hooking
     * dlopen() on Android, where the dynamic linker uses the caller address
     * to decide on namespace and whether to allow the particular library to
     * be used by a particular caller.
     *
     * Because we potentially replace LR in order to trap the return, we end
     * up breaking dlopen() in such cases. We work around this by detecting
     * LR being read, and replace that instruction with a load of the actual
     * caller.
     *
     * This is however a bit risky done blindly, so we try to limit the
     * scope to the bare minimum. A potentially better longer term solution
     * is to analyze the function and patch each point of return, so we don't
     * have to replace LR on entry. That is however a bit complex, so we
     * opt for this simpler solution for now.
     */
    is_eligible_for_lr_rewriting = strcmp (signature->str, "mov;b") == 0 ||
        strcmp (signature->str, "mov;bx") == 0 ||
        g_str_has_prefix (signature->str, "push;mov;bl");

    g_string_free (signature, TRUE);

    if (is_eligible_for_lr_rewriting)
    {
      const cs_insn * insn;

      while ((insn = gum_thumb_relocator_peek_next_write_insn (tr)) != NULL)
      {
        if (insn->id == ARM_INS_MOV &&
            insn->detail->arm.operands[1].reg == ARM_REG_LR)
        {
          arm_reg dst_reg = insn->detail->arm.operands[0].reg;
          const arm_reg clobbered_regs[] = {
            ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
            ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
            ARM_REG_R9, ARM_REG_R12, ARM_REG_LR,
          };
          GArray * saved_regs;
          guint i;
          arm_reg nzcvq_reg;

          saved_regs = g_array_sized_new (FALSE, FALSE, sizeof (arm_reg),
              G_N_ELEMENTS (clobbered_regs));
          for (i = 0; i != G_N_ELEMENTS (clobbered_regs); i++)
          {
            arm_reg reg = clobbered_regs[i];
            if (reg != dst_reg)
              g_array_append_val (saved_regs, reg);
          }

          nzcvq_reg = ARM_REG_R4;
          if (nzcvq_reg == dst_reg)
            nzcvq_reg = ARM_REG_R5;

          gum_thumb_writer_put_push_regs_array (tw, saved_regs->len,
              (const arm_reg *) saved_regs->data);
          gum_thumb_writer_put_mrs_reg_reg (tw, nzcvq_reg,
              ARM_SYSREG_APSR_NZCVQ);

          gum_thumb_writer_put_call_address_with_arguments (tw,
              GUM_ADDRESS (_gum_interceptor_translate_top_return_address), 1,
              GUM_ARG_REGISTER, ARM_REG_LR);
          gum_thumb_writer_put_mov_reg_reg (tw, dst_reg, ARM_REG_R0);

          gum_thumb_writer_put_msr_reg_reg (tw, ARM_SYSREG_APSR_NZCVQ,
              nzcvq_reg);
          gum_thumb_writer_put_pop_regs_array (tw, saved_regs->len,
              (const arm_reg *) saved_regs->data);

          g_array_free (saved_regs, TRUE);

          gum_thumb_relocator_skip_one (tr);
        }
        else
        {
          gum_thumb_relocator_write_one (tr);
        }
      }
    }
    else
    {
      gum_thumb_relocator_write_all (tr);
    }

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
      if (reloc_bytes == 0)
        reloc_bytes = data->redirect_code_size;
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
  g_assert (gum_thumb_writer_offset (tw) <= ctx->trampoline_slice->size);

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
  GumAddress function_address;
  GumArmFunctionContextData * data = (GumArmFunctionContextData *)
      &ctx->backend_data;

  function_address = GUM_ADDRESS (
      _gum_interceptor_backend_get_function_address (ctx));

  if (FUNCTION_CONTEXT_ADDRESS_IS_THUMB (ctx))
  {
    GumThumbWriter * tw = &self->thumb_writer;

    gum_thumb_writer_reset (tw, prologue);
    tw->pc = function_address;

    if (ctx->trampoline_deflector != NULL)
    {
      if (data->redirect_code_size == GUM_INTERCEPTOR_THUMB_LINK_REDIRECT_SIZE)
      {
        gum_emit_push_cpu_context_high_part (tw);
        gum_thumb_writer_put_bl_imm (tw,
            GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
      }
      else
      {
        g_assert (data->redirect_code_size ==
            GUM_INTERCEPTOR_THUMB_TINY_REDIRECT_SIZE);
        gum_thumb_writer_put_b_imm (tw,
            GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
      }
    }
    else
    {
      gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_PC,
          GUM_ADDRESS (ctx->on_enter_trampoline));
    }

    gum_thumb_writer_flush (tw);
    g_assert (gum_thumb_writer_offset (tw) <= data->redirect_code_size);
  }
  else
  {
    GumArmWriter * aw = &self->arm_writer;

    gum_arm_writer_reset (aw, prologue);
    aw->pc = function_address;

    if (ctx->trampoline_deflector != NULL)
    {
      g_assert (data->redirect_code_size ==
          GUM_INTERCEPTOR_ARM_TINY_REDIRECT_SIZE);
      gum_arm_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
          GUM_ADDRESS (ctx->on_enter_trampoline));
    }

    gum_arm_writer_flush (aw);
    g_assert (gum_arm_writer_offset (aw) == data->redirect_code_size);
  }
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  memcpy (prologue, ctx->overwritten_prologue, ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ctx->function_address) & ~((gsize) 1));
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

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumThumbWriter * tw = &self->thumb_writer;

  self->thunks = gum_code_allocator_alloc_slice (self->allocator);

  gum_thumb_writer_reset (tw, self->thunks->data);

  self->enter_thunk = gum_thumb_writer_cur (tw) + 1;
  gum_emit_enter_thunk (tw);

  self->leave_thunk = gum_thumb_writer_cur (tw) + 1;
  gum_emit_leave_thunk (tw);

  gum_thumb_writer_flush (tw);
  g_assert (gum_thumb_writer_offset (tw) <= self->thunks->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_free (self->thunks);
}

static void
gum_emit_enter_thunk (GumThumbWriter * tw)
{
  gum_emit_prolog (tw);

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

  gum_emit_epilog (tw);
}

static void
gum_emit_leave_thunk (GumThumbWriter * tw)
{
  gum_emit_prolog (tw);

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R2, ARM_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_thumb_writer_put_call_address_with_arguments (tw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM_REG_R7,
      GUM_ARG_REGISTER, ARM_REG_R1,
      GUM_ARG_REGISTER, ARM_REG_R2);

  gum_emit_epilog (tw);
}

static void
gum_emit_push_cpu_context_high_part (GumThumbWriter * tw)
{
  gum_thumb_writer_put_push_regs (tw, 8 + 1,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
      ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
      ARM_REG_LR);
}

static void
gum_emit_prolog (GumThumbWriter * tw)
{
  /*
   * Set up our stack frame:
   *
   * [cpu_context] <-- high part already pushed
   * [next_hop]
   */

  /* build middle part of GumCpuContext */
  gum_thumb_writer_put_push_regs (tw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R1, ARM_REG_SP,
      (5 + 9) * 4);
  gum_thumb_writer_put_push_regs (tw, 2, ARM_REG_R0, ARM_REG_R1);

  /* reserve space for next_hop and for cpsr in GumCpuContext */
  gum_thumb_writer_put_sub_reg_imm (tw, ARM_REG_SP, 8);
}

static void
gum_emit_epilog (GumThumbWriter * tw)
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

  /* restore middle part */
  gum_thumb_writer_put_pop_regs (tw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  /* restore r[0-8] and jump straight to LR */
  gum_thumb_writer_put_pop_regs (tw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
      ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
      ARM_REG_PC);
}
