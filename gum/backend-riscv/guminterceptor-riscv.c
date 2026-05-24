/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumriscvreader.h"
#include "gumriscvrelocator.h"
#include "gumriscvwriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>


#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))
#define GUM_FRAME_OFFSET_PADDING \
    (GUM_FRAME_OFFSET_NEXT_HOP + sizeof (gpointer))
#define GUM_STACK_FRAME_SIZE \
    ((GUM_FRAME_OFFSET_PADDING + sizeof (gpointer) + 15) & ~15)

#define GUM_FCDATA(context) \
    ((GumRiscvFunctionContextData *) (context)->backend_data.storage)


#define GUM_RISCV_TINY_REDIRECT_SIZE 4
#define GUM_RISCV_FULL_REDIRECT_SIZE 8


#define GUM_RISCV_AUIPC_MAX_DISTANCE G_GINT64_CONSTANT (0x7fffffff)


#define GUM_RISCV_JAL_MAX_DISTANCE (1 << 20)

typedef struct _GumRiscvFunctionContextData GumRiscvFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumRiscvWriter writer;
  GumRiscvRelocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumRiscvFunctionContextData
{
  guint redirect_code_size;
  riscv_reg scratch_reg;
};

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumRiscvWriter * cw);
static void gum_emit_leave_thunk (GumRiscvWriter * cw);

static void gum_emit_prolog (GumRiscvWriter * cw);
static void gum_emit_epilog (GumRiscvWriter * cw);

static void gum_riscv_writer_put_branch_to_address (GumRiscvWriter * cw,
    riscv_reg scratch_reg, GumAddress target);

static gboolean gum_interceptor_backend_prepare_trampoline (
    GumInterceptorBackend * self,
    GumFunctionContext * ctx);

 GumInterceptorBackend *
 _gum_interceptor_backend_create (GRecMutex * mutex,
                                  GumCodeAllocator * allocator)
 {
   GumInterceptorBackend * backend;
 
   backend = g_slice_new (GumInterceptorBackend);
   backend->allocator = allocator;
 
   gum_riscv_writer_init (&backend->writer, NULL);
   gum_riscv_relocator_init (&backend->relocator, NULL, &backend->writer);
 
   gum_interceptor_backend_create_thunks (backend);
 
  return backend;
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address = ctx->function_address;
  guint redirect_limit;


  if (gum_riscv_relocator_can_relocate (function_address,
      GUM_RISCV_FULL_REDIRECT_SIZE, GUM_SCENARIO_ONLINE, &redirect_limit,
      &data->scratch_reg))
  {
    GumAddressSpec spec;

    data->redirect_code_size = GUM_RISCV_FULL_REDIRECT_SIZE;


    spec.near_address = function_address;
    spec.max_distance = GUM_RISCV_AUIPC_MAX_DISTANCE;

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, 0);
    if (ctx->trampoline_slice == NULL)
    {

      return FALSE;
    }
  }
  else
  {
    GumAddressSpec spec;


    if (redirect_limit >= GUM_RISCV_TINY_REDIRECT_SIZE)
    {
      data->redirect_code_size = GUM_RISCV_TINY_REDIRECT_SIZE;


      if (data->scratch_reg == RISCV_REG_INVALID)
      {
        guint dummy_limit;
        if (!gum_riscv_relocator_can_relocate (function_address,
            GUM_RISCV_TINY_REDIRECT_SIZE, GUM_SCENARIO_ONLINE, &dummy_limit,
            &data->scratch_reg))
        {
          return FALSE;
        }
      }

      spec.near_address = function_address;
      spec.max_distance = GUM_RISCV_JAL_MAX_DISTANCE;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, 0);
    if (ctx->trampoline_slice == NULL)
    {

      return FALSE;
    }
  }

  if (data->scratch_reg == RISCV_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumRiscvWriter * cw = &self->writer;
  GumRiscvRelocator * rl = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_riscv_writer_reset (cw, ctx->trampoline_slice->data);
  cw->pc = GUM_ADDRESS (ctx->trampoline_slice->pc);

  ctx->on_enter_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);


  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T0, GUM_ADDRESS (ctx));

  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1,
      GUM_ADDRESS (self->enter_thunk->pc));

  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);

  ctx->on_leave_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);


  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T0, GUM_ADDRESS (ctx));

  gum_riscv_writer_put_la_reg_address (cw, RISCV_REG_T1,
      GUM_ADDRESS (self->leave_thunk->pc));

  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);

  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline =
      ctx->trampoline_slice->pc + gum_riscv_writer_offset (cw);

  gum_riscv_relocator_reset (rl, function_address, cw);

  do
  {
    reloc_bytes = gum_riscv_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);

  }
  while (reloc_bytes < data->redirect_code_size);

  gum_riscv_relocator_write_all (rl);

  if (!gum_riscv_relocator_eoi (rl))
  {
    GumAddress resume_at;

    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
    gum_riscv_writer_put_la_reg_address (cw, data->scratch_reg, resume_at);
    gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, data->scratch_reg, 0);
  }

  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= ctx->trampoline_slice->size);

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

static void
gum_riscv_writer_put_branch_to_address (GumRiscvWriter * cw,
                                        riscv_reg scratch_reg,
                                        GumAddress target)
{

  gint64 offset = (gint64) target - (gint64) cw->pc;


  if (offset >= G_GINT64_CONSTANT (-0x80000000) &&
      offset <= G_GINT64_CONSTANT (0x7fffffff))
  {

    gint32 lo12 = offset & 0xfff;
    if (lo12 >= 0x800)
      lo12 -= 0x1000;
    gint32 hi20 = (gint32) ((offset - lo12) >> 12);

    gum_riscv_writer_put_auipc_reg_imm (cw, scratch_reg, hi20);
    gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, scratch_reg, lo12);
  }
  else
  {

    gum_riscv_writer_put_la_reg_address (cw, scratch_reg, target);
    gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, scratch_reg, 0);
  }
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumRiscvWriter * cw = &self->writer;
  GumRiscvFunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter;

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    on_enter = GUM_ADDRESS (ctx->replacement_function);
  else
    on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_riscv_writer_reset (cw, prologue);
  cw->pc = GUM_ADDRESS (ctx->function_address);


  switch (data->redirect_code_size)
  {
    case GUM_RISCV_TINY_REDIRECT_SIZE:

      gum_riscv_writer_put_jal_imm (cw, on_enter);
      break;
    case GUM_RISCV_FULL_REDIRECT_SIZE:
    {
      gint64 offset = (gint64) on_enter - (gint64) cw->pc;


      if (offset >= G_GINT64_CONSTANT (-0x80000000) &&
          offset <= G_GINT64_CONSTANT (0x7fffffff))
      {
        gint32 lo12 = offset & 0xfff;
        gint32 hi20;

        if (lo12 >= 0x800)
          lo12 -= 0x1000;
        hi20 = (gint32) ((offset - lo12) >> 12);

        gum_riscv_writer_put_auipc_reg_imm (cw, data->scratch_reg, hi20);
        gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, data->scratch_reg, lo12);
      }
      else
      {
        gum_riscv_writer_put_la_reg_address (cw, data->scratch_reg, on_enter);
        gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, data->scratch_reg, 0);
      }
      break;
    }
    default:
      g_assert_not_reached ();
  }

  gum_riscv_writer_flush (cw);
  

  guint written_bytes = gum_riscv_writer_offset (cw);
  g_assert (written_bytes <= ctx->overwritten_prologue_len);
  
  if (written_bytes < ctx->overwritten_prologue_len)
  {

    guint padding_bytes = ctx->overwritten_prologue_len - written_bytes;
    
    while (written_bytes < ctx->overwritten_prologue_len)
    {
      guint remaining = ctx->overwritten_prologue_len - written_bytes;
      
      if (remaining >= 4)
      {
        gum_riscv_writer_put_nop (cw);
        written_bytes += 4;
      }
      else if (remaining >= 2)
      {

        guint16 c_nop = 0x0001;
        gum_riscv_writer_put_bytes (cw, (const guint8 *) &c_nop, 2);
        written_bytes += 2;
      }
      else
      {
        g_assert_not_reached ();
      }
    }
    
    gum_riscv_writer_flush (cw);
    g_assert (gum_riscv_writer_offset (cw) == ctx->overwritten_prologue_len);
  }
  else
  {
    g_assert (written_bytes == ctx->overwritten_prologue_len);
  }
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
  GumAddress target;

  (void) self;

  if (!gum_riscv_reader_try_get_relative_jump_info (address, &target, NULL))
    return NULL;

  return GSIZE_TO_POINTER (target);
 }
 
 gsize
 _gum_interceptor_backend_detect_hook_size (gconstpointer code,
                                            csh capstone,
                                            cs_insn * insn)
 {
  gsize hook_size;

  (void) capstone;
  (void) insn;

  if (!gum_riscv_reader_try_get_relative_jump_info (code, NULL, &hook_size))
    return 0;

  return hook_size;
 }

 void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_riscv_relocator_clear (&backend->relocator);
  gum_riscv_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumRiscvWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_riscv_writer_reset (cw, self->enter_thunk->data);
  cw->pc = GUM_ADDRESS (self->enter_thunk->pc);
  gum_emit_enter_thunk (cw);
  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_riscv_writer_reset (cw, self->leave_thunk->data);
  cw->pc = GUM_ADDRESS (self->leave_thunk->pc);
  gum_emit_leave_thunk (cw);
  gum_riscv_writer_flush (cw);
  g_assert (gum_riscv_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);
  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumRiscvWriter * cw)
{
  gum_emit_prolog (cw);


  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, t0));

  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A1, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);


  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A2, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, ra));


  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A3, RISCV_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);


  gum_riscv_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, RISCV_REG_A0, 
      GUM_ARG_REGISTER, RISCV_REG_A1, 
      GUM_ARG_REGISTER, RISCV_REG_A2, 
      GUM_ARG_REGISTER, RISCV_REG_A3); 

  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumRiscvWriter * cw)
{

  gum_emit_prolog (cw);

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, t0));


  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A1, RISCV_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);

  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_A2, RISCV_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_riscv_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, RISCV_REG_A0, 
      GUM_ARG_REGISTER, RISCV_REG_A1, 
      GUM_ARG_REGISTER, RISCV_REG_A2);

  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumRiscvWriter * cw)
{


  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      -((gint32) GUM_STACK_FRAME_SIZE));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t6));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t5));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t4));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t3));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S11, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s11));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S10, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s10));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S9, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s9));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S8, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s8));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S7, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s7));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s6));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s5));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s4));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s3));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s2));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A7, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a7));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a6));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a5));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a4));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a3));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a2));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a1));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a0));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s1));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_S0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s0));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t2));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t1));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t0));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_TP, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, tp));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_GP, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, gp));

  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_T1, RISCV_REG_SP,
      GUM_STACK_FRAME_SIZE);

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_T1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, sp));

  gum_riscv_writer_put_sd_reg_reg_offset (cw, RISCV_REG_RA, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, ra));

}

static void
gum_emit_epilog (GumRiscvWriter * cw)
{

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_RA, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, ra));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_GP, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, gp));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_TP, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, tp));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s0));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s1));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a0));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A1, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a1));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a2));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a3));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a4));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a5));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a6));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_A7, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, a7));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s2));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s3));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s4));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s5));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s6));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S7, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s7));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S8, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s8));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S9, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s9));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S10, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s10));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_S11, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, s11));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T3, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t3));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T4, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t4));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T5, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t5));
  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T6, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t6));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T2, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t2));

  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T0, RISCV_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, t0));


  gum_riscv_writer_put_ld_reg_reg_offset (cw, RISCV_REG_T1, RISCV_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_riscv_writer_put_addi_reg_reg_imm (cw, RISCV_REG_SP, RISCV_REG_SP,
      GUM_STACK_FRAME_SIZE);

  gum_riscv_writer_put_jalr_reg (cw, RISCV_REG_ZERO, RISCV_REG_T1, 0);
}
