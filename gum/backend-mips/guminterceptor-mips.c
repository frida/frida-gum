/*
 * Copyright (C) 2014-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

/*
 * This constant represents the size of the hook assembly sequence which
 * is to be written over the prologue of the intercepted function. This
 * is a minimalist stub which simply vectors to the larger trampoline which
 * stores the CPU context and transitions to C code passing the necessary
 * landmarks.
 *
 * On MIPS64, whilst data access can be 64 bits wide, the instruction stream
 * is only 32 bits. With fixed width 32-bit instructions, it is only possible
 * to load 16 bit immediate values at a time. Hence loading a 64-bit immediate
 * value takes rather more instructions.
 */
#if GLIB_SIZEOF_VOID_P == 8
# define GUM_HOOK_SIZE 28
#else
# define GUM_HOOK_SIZE 16
#endif

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof(GumCpuContext))

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
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
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

  gum_mips_relocator_clear (&backend->relocator);
  gum_mips_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
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

  if (gum_mips_relocator_can_relocate (function_address, GUM_HOOK_SIZE,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = GUM_HOOK_SIZE;

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
  }

  /* TODO: save $t0 on the stack? */

#if GLIB_SIZEOF_VOID_P == 8
  /*
   * On MIPS64 the calling convention is that 8 arguments are passed in
   * registers. The additional registers used for these arguments are a4-a7,
   * these replace the registers t0-t3 used in MIPS32. Hence t4 is now our first
   * available register, otherwise we will start clobbering function parameters.
   */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T4, GUM_ADDRESS (ctx));
#else
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
#endif
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->enter_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  ctx->on_leave_trampoline = gum_mips_writer_cur (cw);

  /* TODO: save $t0 on the stack? */
#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T4, GUM_ADDRESS (ctx));
#else
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
#endif
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->leave_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_mips_writer_cur (cw);

  /* Fix t9 to point to the original function address */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T9,
      GUM_ADDRESS (function_address));

  gum_mips_relocator_reset (rl, function_address, cw);

  do
  {
    reloc_bytes = gum_mips_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
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
  g_assert (gum_mips_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
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
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 8:
        gum_mips_writer_put_j_address (cw, on_enter);
        break;
      case GUM_HOOK_SIZE:
#if GLIB_SIZEOF_VOID_P == 8
        /*
         * On MIPS64 loading a 64-bit immediate requires 16-bits of the
         * immediate to be loaded at a time since instructions are only 32-bits
         * wide. This results in a large number of instructions both for the
         * loading as well as logical shifting of the immediate.
         *
         * Therefore on 64-bit platforms we instead embed the immediate in the
         * code stream and read its value from there. However, we need to know
         * the address from which to load the value. Since our hook is to be
         * written over the prolog of an existing function, we can rely upon
         * this.
         *
         * MIPS has no architectural visibility of the instruction pointer.
         * That is its value cannot be read and there is no RIP-relative
         * addressing. Therefore convention is that a general purpose register
         * (T9) is set to the address of the function to be called. We can
         * therefore use this register to locate the immediate we need to load.
         * However, this mechanism only works for loading immediates for the
         * hook since if we are writing instructions to load an immediate
         * elsewhere, we don't know how far our RIP is from the start of the
         * function. However, in these cases we don't care about code size and
         * we can instead revert to the old method of shuffling 16-bits at
         * a time.
         */
        gum_mips_writer_put_prologue_trampoline (cw, MIPS_REG_AT, on_enter);
#else
        gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT, on_enter);
        gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);
#endif
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
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
  return NULL;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumMipsWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);

  gum_code_slice_unref (self->enter_thunk);
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

#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, MIPS_REG_T4,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2,  /* return_address */
      GUM_ARG_REGISTER, MIPS_REG_A3); /* next_hop */
#else
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2,  /* return_address */
      GUM_ARG_REGISTER, MIPS_REG_A3); /* next_hop */
#endif

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
#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T4,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2); /* next_hop */
#else
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2); /* next_hop */
#endif

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

  /* Reserve space for next_hop. */
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);

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

  /*
   * SP
   *
   * Here we are calculating the original stack pointer (before we stored) all
   * the context above and saving it to the stack so that it can be read as part
   * of the CpuContext structure.
   */
#if GLIB_SIZEOF_VOID_P == 8
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      8 + (30 * 8));
#else
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      4 + (30 * 4));
#endif
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_GP);

  /* Dummy PC */
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);
}

static void
gum_emit_epilog (GumMipsWriter * cw)
{
  /* Dummy PC */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_GP);

  /* Dummy SP */
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

  /*
   * Pop and jump to the next_hop.
   *
   * This needs to be via t9 so that PIC code works.
   */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_T9);
}
