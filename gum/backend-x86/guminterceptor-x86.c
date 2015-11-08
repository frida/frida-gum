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

static void gum_function_context_write_guard_enter_code (
    GumFunctionContext * ctx, gconstpointer skip_label, GumX86Writer * cw);
static void gum_function_context_write_guard_leave_code (
    GumFunctionContext * ctx, GumX86Writer * cw);

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
_gum_interceptor_backend_make_monitor_trampoline (GumInterceptorBackend * self,
                                                  GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  guint8 zeroed_header[16] = { 0, };
  gconstpointer skip_label = "gum_interceptor_on_enter_skip";
  gconstpointer dont_increment_usage_counter_label =
      "gum_interceptor_on_enter_dont_increment_usage_counter";
  guint reloc_bytes;
  guint align_correction_enter = 8;
  guint align_correction_leave = 0;

#if GLIB_SIZEOF_VOID_P == 4
  align_correction_leave = 4;
#endif

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_x86_writer_reset (cw, ctx->trampoline_slice->data);
  gum_x86_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  /*
   * Keep a usage counter at the start of the trampoline, so we can address
   * it directly on both 32 and 64 bit
   */
  ctx->trampoline_usage_counter = (gint *) gum_x86_writer_cur (cw);
  gum_x86_writer_put_bytes (cw, zeroed_header, sizeof (zeroed_header));

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = (guint8 *) gum_x86_writer_cur (cw);

  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */
  gum_x86_writer_put_lock_inc_imm32_ptr (cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_pushax (cw);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder for xip */

  gum_function_context_write_guard_enter_code (ctx, skip_label, cw);

  /* GumCpuContext fixup of stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSI,
      GUM_REG_XSP, sizeof (GumCpuContext) + 2 * sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XSI);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSI, GUM_REG_XSP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XDI, GUM_REG_XSP,
      sizeof (GumCpuContext) + sizeof (gpointer));

  /* keep stack aligned on 16 byte boundary */
  if (align_correction_enter != 0)
    gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction_enter);

  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_on_enter),
      3,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI);

  if (align_correction_enter != 0)
    gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP, align_correction_enter);

  gum_x86_writer_put_test_reg_reg (cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ,
      dont_increment_usage_counter_label, GUM_UNLIKELY);
  gum_x86_writer_put_lock_inc_imm32_ptr (cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_label (cw, dont_increment_usage_counter_label);

  gum_function_context_write_guard_leave_code (ctx, cw);

  gum_x86_writer_put_label (cw, skip_label);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX); /* clear xip placeholder */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_lock_dec_imm32_ptr (cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_popfx (cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
  gum_x86_relocator_write_all (rl);

  if (!gum_x86_relocator_eoi (rl))
  {
    gum_x86_writer_put_jmp (cw,
        (guint8 *) ctx->function_address + reloc_bytes);
  }

  gum_x86_writer_put_breakpoint (cw);

  ctx->overwritten_prologue_len = reloc_bytes;
  memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  /*
   * Generate on_leave trampoline
   */
  ctx->on_leave_trampoline = gum_x86_writer_cur (cw);

  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder for ret */

  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */
  gum_x86_writer_put_pushax (cw);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder for xip */

  gum_function_context_write_guard_enter_code (ctx, NULL, cw);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSI, GUM_REG_XSP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XDI,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer));

  /* align stack on 16 byte boundary */
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, 16 - 1);
#if GLIB_SIZEOF_VOID_P == 8
  gum_x86_writer_put_mov_reg_u64 (cw, GUM_REG_RDX,
      G_GUINT64_CONSTANT (0xfffffffffffffff0));
#else
  gum_x86_writer_put_mov_reg_u32 (cw, GUM_REG_EDX, 0xfffffff0);
#endif
  gum_x86_writer_put_and_reg_reg (cw, GUM_REG_XSP, GUM_REG_XDX);

  if (align_correction_leave != 0)
    gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction_leave);

  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_on_leave),
      3,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBP);

  gum_function_context_write_guard_leave_code (ctx, cw);

  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX); /* clear xip placeholder */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_lock_dec_imm32_ptr (cw,
      (gpointer) ctx->trampoline_usage_counter);
  gum_x86_writer_put_popfx (cw);

  gum_x86_writer_put_ret (cw);

  gum_x86_writer_flush (cw);
  g_assert_cmpuint (gum_x86_writer_offset (cw),
      <=, ctx->trampoline_slice->size);

  return TRUE;
}

gboolean
_gum_interceptor_backend_make_replace_trampoline (GumInterceptorBackend * self,
                                                  GumFunctionContext * ctx)
{
  gconstpointer skip_label = "gum_interceptor_replacement_skip";
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  ctx->on_leave_trampoline = ctx->trampoline_slice->data;
  gum_x86_writer_reset (cw, ctx->on_leave_trampoline);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder */
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XDX);
  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_end_invocation), 0);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, 2 * sizeof (gpointer),
      GUM_REG_XAX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XDX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_ret (cw);

  ctx->on_enter_trampoline = gum_x86_writer_cur (cw);

  gum_x86_writer_put_pushax (cw);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder */

  /* GumCpuContext fixup of stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XAX,
      GUM_REG_XSP, sizeof (GumCpuContext) + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_REG_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_XSI,
      GUM_REG_XSP, sizeof (GumCpuContext));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XDI, GUM_REG_XSP);
  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (_gum_function_context_try_begin_invocation), 3,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ, skip_label,
      GUM_NO_HINT);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_popax (cw);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (ctx->on_leave_trampoline));
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_REG_XSP, GUM_REG_XAX);
  gum_x86_writer_put_jmp (cw, ctx->replacement_function);

  gum_x86_writer_put_label (cw, skip_label);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_popax (cw);

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
    gum_x86_writer_put_jmp (cw,
        (guint8 *) ctx->function_address + reloc_bytes);
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

static void
gum_function_context_write_guard_enter_code (GumFunctionContext * ctx,
                                             gconstpointer skip_label,
                                             GumX86Writer * cw)
{
#ifdef HAVE_DARWIN
  const guint32 guard_offset = _gum_interceptor_guard_key * GLIB_SIZEOF_VOID_P;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (ctx->interceptor));

  if (skip_label != NULL)
  {
# if GLIB_SIZEOF_VOID_P == 4
    guint8 check[] = {
      0x65, 0x39, 0x05,             /* cmp [gs:0x12345678], eax */
      0x78, 0x56, 0x34, 0x12
    };
    *((guint32 *) (check + 3)) = guard_offset;
# else
    guint8 check[] = {
      0x65, 0x48, 0x39, 0x04, 0x25, /* cmp [gs:0x12345678], rax */
      0x78, 0x56, 0x34, 0x12
    };
    *((guint32 *) (check + 5)) = guard_offset;
# endif
    gum_x86_writer_put_bytes (cw, check, sizeof (check));
    gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ, skip_label,
        GUM_UNLIKELY);
  }

# if GLIB_SIZEOF_VOID_P == 4
  guint8 enable_guard[] = {
    0x65, 0xa3,                     /* mov [gs:0x12345678], eax */
    0x78, 0x56, 0x34, 0x12
  };
  *((guint32 *) (enable_guard + 2)) = guard_offset;
# else
  guint8 enable_guard[] = {
    0x65, 0x48, 0x89, 0x04, 0x25,   /* mov [gs:0x12345678], rax */
    0x78, 0x56, 0x34, 0x12
  };
  *((guint32 *) (enable_guard + 5)) = guard_offset;
# endif
  gum_x86_writer_put_bytes (cw, enable_guard, sizeof (enable_guard));
#else
  (void) ctx;
  (void) skip_label;
  (void) cw;
#endif
}

static void
gum_function_context_write_guard_leave_code (GumFunctionContext * ctx,
                                             GumX86Writer * cw)
{
#ifdef HAVE_DARWIN
  const guint32 guard_offset = _gum_interceptor_guard_key * GLIB_SIZEOF_VOID_P;

# if GLIB_SIZEOF_VOID_P == 4
  guint8 disable_guard[] = {
    0x65, 0xc7, 0x05,               /* mov dword [dword gs:0x12345678], 0 */
    0x78, 0x56, 0x34, 0x12,
    0x00, 0x00, 0x00, 0x00
  };
  *((guint32 *) (disable_guard + 3)) = guard_offset;
# else
  guint8 disable_guard[] = {
    0x65, 0x48, 0xc7, 0x04, 0x25,   /* mov qword [gs:0x12345678], 0 */
    0x78, 0x56, 0x34, 0x12,
    0x00, 0x00, 0x00, 0x00
  };
  *((guint32 *) (disable_guard + 5)) = guard_offset;
# endif
  gum_x86_writer_put_bytes (cw, disable_guard, sizeof (disable_guard));
#else
  (void) ctx;
  (void) cw;
#endif
}
