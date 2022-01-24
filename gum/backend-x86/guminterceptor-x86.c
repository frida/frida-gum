/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumlibc.h"
#include "gummemory.h"
#include "gumsysinternals.h"
#include "gumx86reader.h"
#include "gumx86relocator.h"

#include <string.h>

#define GUM_INTERCEPTOR_FULL_REDIRECT_SIZE  16
#define GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE  5
#define GUM_X86_JMP_MAX_DISTANCE            (G_MAXINT32 - 16384)

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_CPU_FLAGS \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_FLAGS + sizeof (gpointer))
#define GUM_FRAME_OFFSET_TOP \
    (GUM_FRAME_OFFSET_NEXT_HOP + sizeof (gpointer))

typedef struct _GumX86FunctionContextData GumX86FunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumX86Writer writer;
  GumX86Relocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumX86FunctionContextData
{
  guint redirect_code_size;
};

G_STATIC_ASSERT (sizeof (GumX86FunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumX86Writer * cw);
static void gum_emit_leave_thunk (GumX86Writer * cw);

static void gum_emit_prolog (GumX86Writer * cw,
    gssize stack_displacement);
static void gum_emit_epilog (GumX86Writer * cw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_x86_writer_init (&backend->writer, NULL);
  gum_x86_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_x86_relocator_clear (&backend->relocator);
  gum_x86_writer_clear (&backend->writer);

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
                                            GumFunctionContext * ctx)
{
  GumX86FunctionContextData * data = (GumX86FunctionContextData *)
      &ctx->backend_data;
#if GLIB_SIZEOF_VOID_P == 4
  data->redirect_code_size = GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE;

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
#else
  GumAddressSpec spec;
  gsize default_alignment = 0;

  spec.near_address = ctx->function_address;
  spec.max_distance = GUM_X86_JMP_MAX_DISTANCE;
  ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
      self->allocator, &spec, default_alignment);
  if (ctx->trampoline_slice != NULL)
  {
    data->redirect_code_size = GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE;
  }
  else
  {
    data->redirect_code_size = GUM_INTERCEPTOR_FULL_REDIRECT_SIZE;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
#endif

  if (!gum_x86_relocator_can_relocate (ctx->function_address,
        data->redirect_code_size, NULL))
    goto not_enough_space;

  return TRUE;

not_enough_space:
  {
    gum_code_slice_unref (ctx->trampoline_slice);
    ctx->trampoline_slice = NULL;
    return FALSE;
  }
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  GumX86FunctionContextData * data = (GumX86FunctionContextData *)
      &ctx->backend_data;
  GumAddress function_ctx_ptr;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_x86_writer_reset (cw, ctx->trampoline_slice->data);

  function_ctx_ptr = GUM_ADDRESS (gum_x86_writer_cur (cw));
  gum_x86_writer_put_bytes (cw, (guint8 *) &ctx, sizeof (GumFunctionContext *));

  ctx->on_enter_trampoline = gum_x86_writer_cur (cw);

  gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->enter_thunk->data));

  ctx->on_leave_trampoline = gum_x86_writer_cur (cw);

  gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->leave_thunk->data));

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_x86_writer_cur (cw);
  gum_x86_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);
  gum_x86_relocator_write_all (rl);

  if (!gum_x86_relocator_eoi (rl))
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (ctx->function_address) + reloc_bytes);
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumX86Writer * cw = &self->writer;
  GumX86FunctionContextData * data G_GNUC_UNUSED = (GumX86FunctionContextData *)
      &ctx->backend_data;
  guint padding;

  gum_x86_writer_reset (cw, prologue);
  cw->pc = GPOINTER_TO_SIZE (ctx->function_address);
  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (ctx->on_enter_trampoline));
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= data->redirect_code_size);

  padding = ctx->overwritten_prologue_len - gum_x86_writer_offset (cw);
  gum_x86_writer_put_nop_padding (cw, padding);
  gum_x86_writer_flush (cw);
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
  gpointer target;

  target = gum_x86_reader_try_get_relative_jump_target (address);
  if (target == NULL)
    target = gum_x86_reader_try_get_indirect_jump_target (address);

  return target;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumX86Writer * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);

  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumX86Writer * cw)
{
  const gssize return_address_stack_displacement = 0;

  gum_emit_prolog (cw, return_address_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSI,
      GUM_REG_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XDX,
      GUM_REG_XBP, GUM_FRAME_OFFSET_TOP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XCX,
      GUM_REG_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, GUM_REG_XBX,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumX86Writer * cw)
{
  const gssize next_hop_stack_displacement = -((gssize) sizeof (gpointer));

  gum_emit_prolog (cw, next_hop_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSI,
      GUM_REG_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XDX,
      GUM_REG_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, GUM_REG_XBX,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDX);

  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumX86Writer * cw,
                 gssize stack_displacement)
{
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };

  /*
   * Set up our stack frame:
   *
   * [next_hop] <-- already pushed before the branch to our thunk
   * [cpu_flags]
   * [cpu_context] <-- xbp points to the start of the cpu_context
   * [alignment_padding]
   * [extended_context]
   */
  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */
  gum_x86_writer_put_pushax (cw); /* all of GumCpuContext except for xip */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, -((gssize) sizeof (gpointer))); /* GumCpuContext.xip */

  /* fixup the GumCpuContext stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XAX,
      GUM_REG_XSP, GUM_FRAME_OFFSET_TOP + stack_displacement);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_XBX, GUM_REG_XSP,
      GUM_FRAME_OFFSET_NEXT_HOP);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_REG_XSP, (guint32) ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));
}

static void
gum_emit_epilog (GumX86Writer * cw)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };

  gum_x86_writer_put_bytes (cw, fxrstor, sizeof (fxrstor));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBP);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, sizeof (gpointer)); /* discard
                                          GumCpuContext.xip */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_ret (cw);
}
