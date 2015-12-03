/*
 * Copyright (C) 2008-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gummemory.h"
#include "gumsysinternals.h"
#include "gumx86reader.h"
#include "gumx86relocator.h"

#include <string.h>

#define GUM_INTERCEPTOR_REDIRECT_CODE_SIZE  5
#define GUM_INTERCEPTOR_GUARD_MAGIC         0x47756D21
#define GUM_X86_JMP_MAX_DISTANCE            (G_MAXINT32 - 16384)

struct _GumInterceptorBackend
{
  GumX86Writer writer;
  GumX86Relocator relocator;
};

GumInterceptorBackend *
_gum_interceptor_backend_create (GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  (void) allocator;

  backend = g_slice_new (GumInterceptorBackend);

  gum_x86_writer_init (&backend->writer, NULL);
  gum_x86_relocator_init (&backend->relocator, NULL, &backend->writer);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_x86_relocator_free (&backend->relocator);
  gum_x86_writer_free (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  (void) self;

#if GLIB_SIZEOF_VOID_P == 4
  ctx->trampoline_slice = gum_code_allocator_alloc_slice (ctx->allocator);

  return TRUE;
#else
  GumAddressSpec spec;
  gsize default_alignment = 0;

  spec.near_address = ctx->function_address;
  spec.max_distance = GUM_X86_JMP_MAX_DISTANCE;
  ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
      ctx->allocator, &spec, default_alignment);

  return ctx->trampoline_slice != NULL;
#endif
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  gconstpointer skip_label = "gum_interceptor_skip";
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  guint align_correction_enter = 8;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  ctx->on_leave_trampoline = ctx->trampoline_slice->data;
  gum_x86_writer_reset (cw, ctx->on_leave_trampoline);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, -((gssize) sizeof (gpointer)));
  /* xsp: redirect goes here */

  gum_x86_writer_put_pushax (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, -((gssize) sizeof (gpointer))); /* xip placeholder */
  /* xsp: GumCpuContext starts here */

  /* fixup the GumCpuContext stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XAX,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSI, GUM_REG_XSP);

  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_end_invocation), 2,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, 2 * sizeof (gpointer),
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_XSP,
      sizeof (GumCpuContext), GUM_REG_XAX);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, sizeof (gpointer)); /* xip placeholder */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_ret (cw); /* redirect */

  ctx->on_enter_trampoline = gum_x86_writer_cur (cw);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, -((gssize) sizeof (gpointer)));
  /* xsp: redirect goes here */

  gum_x86_writer_put_pushax (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, -((gssize) sizeof (gpointer))); /* xip placeholder */
  /* xsp: GumCpuContext starts here */

  /* fixup the GumCpuContext stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XAX,
      GUM_REG_XSP, sizeof (GumCpuContext) + (2 * sizeof (gpointer)));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_XSI,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XDI, GUM_REG_XSP);

  /* keep stack aligned on 16 byte boundary */
  if (align_correction_enter != 0)
    gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction_enter);

  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_try_begin_invocation), 3,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ, skip_label,
      GUM_NO_HINT);

  if (align_correction_enter != 0)
    gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP, align_correction_enter);

  /* replace the return address so we can trap the return */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (ctx->on_leave_trampoline));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_XSP,
      sizeof (GumCpuContext) + sizeof (gpointer), GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (&ctx->replacement_function));
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XAX);
  gum_x86_writer_put_test_reg_reg (cw, GUM_REG_XAX, GUM_REG_XAX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ, skip_label,
      GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_XSP,
      sizeof (GumCpuContext), GUM_REG_XAX);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, sizeof (gpointer)); /* xip placeholder */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_ret (cw); /* redirect */

  gum_x86_writer_put_label (cw, skip_label);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, sizeof (gpointer)); /* xip placeholder */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSP,
      GUM_REG_XSP, sizeof (gpointer)); /* no redirect */

  gum_x86_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
  gum_x86_relocator_write_all (rl);

  if (!gum_x86_relocator_eoi (rl))
  {
    gum_x86_writer_put_jmp (cw, (guint8 *) ctx->function_address + reloc_bytes);
  }

  gum_x86_writer_put_breakpoint (cw);

  gum_x86_writer_flush (cw);
  g_assert_cmpuint (gum_x86_writer_offset (cw),
      <=, ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  (void) self;

  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  guint padding;

  gum_x86_writer_reset (cw, ctx->function_address);
  gum_x86_writer_put_jmp (cw, ctx->on_enter_trampoline);
  gum_x86_writer_flush (cw);
  g_assert_cmpint (gum_x86_writer_offset (cw),
      <=, GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);

  padding = ctx->overwritten_prologue_len - gum_x86_writer_offset (cw);
  for (; padding != 0; padding--)
    gum_x86_writer_put_nop (cw);
  gum_x86_writer_flush (cw);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx)
{
  (void) self;

  gum_mprotect (ctx->function_address, 16, GUM_PAGE_RWX);
  memcpy (ctx->function_address, ctx->overwritten_prologue,
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
  gpointer target;

  (void) self;

  target = gum_x86_reader_try_get_relative_jump_target (address);
  if (target == NULL)
    target = gum_x86_reader_try_get_indirect_jump_target (address);

  return target;
}

gboolean
_gum_interceptor_backend_can_intercept (GumInterceptorBackend * self,
                                        gpointer function_address)
{
  (void) self;

  return gum_x86_relocator_can_relocate (function_address,
      GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
}

gpointer
_gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                              guint n)
{
  gpointer * stack_argument;

#if GLIB_SIZEOF_VOID_P == 4
  stack_argument = (gpointer *) context->cpu_context->esp;
  return stack_argument[n];
#else
  stack_argument = (gpointer *) context->cpu_context->rsp;
  switch (n)
  {
# if GUM_NATIVE_ABI_IS_UNIX
    case 0:   return (gpointer) context->cpu_context->rdi;
    case 1:   return (gpointer) context->cpu_context->rsi;
    case 2:   return (gpointer) context->cpu_context->rdx;
    case 3:   return (gpointer) context->cpu_context->rcx;
    case 4:   return (gpointer) context->cpu_context->r8;
    case 5:   return (gpointer) context->cpu_context->r9;
    default:  return            stack_argument[n - 6];
# else
    case 0:   return (gpointer) context->cpu_context->rcx;
    case 1:   return (gpointer) context->cpu_context->rdx;
    case 2:   return (gpointer) context->cpu_context->r8;
    case 3:   return (gpointer) context->cpu_context->r9;
    default:  return            stack_argument[n];
# endif
  }
#endif
}

void
_gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context,
    guint n,
    gpointer value)
{
  gpointer * stack_argument;

#if GLIB_SIZEOF_VOID_P == 4
  stack_argument = (gpointer *) context->cpu_context->esp;
  stack_argument[n] = value;
#else
  stack_argument = (gpointer *) context->cpu_context->rsp;
  switch (n)
  {
# if GUM_NATIVE_ABI_IS_UNIX
    case 0:   context->cpu_context->rdi = (guint64) value; break;
    case 1:   context->cpu_context->rsi = (guint64) value; break;
    case 2:   context->cpu_context->rdx = (guint64) value; break;
    case 3:   context->cpu_context->rcx = (guint64) value; break;
    case 4:   context->cpu_context->r8  = (guint64) value; break;
    case 5:   context->cpu_context->r9  = (guint64) value; break;
    default:  stack_argument[n - 6]     =           value; break;
# else
    case 0:   context->cpu_context->rcx = (guint64) value; break;
    case 1:   context->cpu_context->rdx = (guint64) value; break;
    case 2:   context->cpu_context->r8  = (guint64) value; break;
    case 3:   context->cpu_context->r9  = (guint64) value; break;
    default:  stack_argument[n]         =           value; break;
# endif
  }
#endif
}

gpointer
_gum_interceptor_invocation_get_return_value (GumInvocationContext * context)
{
#if GLIB_SIZEOF_VOID_P == 4
  return (gpointer) context->cpu_context->eax;
#else
  return (gpointer) context->cpu_context->rax;
#endif
}

void
_gum_interceptor_invocation_replace_return_value (
    GumInvocationContext * context,
    gpointer value)
{
#if GLIB_SIZEOF_VOID_P == 4
  context->cpu_context->eax = (guint32) value;
#else
  context->cpu_context->rax = (guint64) value;
#endif
}
