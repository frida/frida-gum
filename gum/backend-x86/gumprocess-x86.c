#include "gumprocess.h"
#include "gumdefs.h"

extern void gum_process_call_function_stub (GumCpuContext * cpu_context,
    gpointer user_data, GumProcessRunOnThreadFunc callback);

gboolean gum_process_has_avx ();
#if defined (_M_X64) || defined (__x86_64__)
void gum_process_fxsave (GumX64FpuRegs * regs);
void gum_process_fxrestore (GumX64FpuRegs * regs);
void gum_process_save_avx (GumX64AvxRegs * regs);
void gum_process_restore_avx (GumX64AvxRegs * regs);
#else
void gum_process_fxsave (GumIA32FpuRegs * regs);
void gum_process_fxrestore (GumIA32FpuRegs * regs);
void gum_process_save_avx (GumIA32AvxRegs * regs);
void gum_process_restore_avx (GumIA32AvxRegs * regs);
#endif

gboolean
gum_process_is_run_on_thread_supported ()
{
  return TRUE;
}

#if defined (_M_X64) || defined (__x86_64__)
void
gum_process_modify_thread_to_call_function (GumThreadId thread_id,
                                            GumCpuContext * cpu_context,
                                            gpointer user_data)
{
  GumProcessRunOnThreadContext * ctx = (GumProcessRunOnThreadContext *) user_data;

  ctx->cached_context = *cpu_context;

  cpu_context->rip = (guint64) gum_process_call_function_stub;

# ifdef HAVE_WINDOWS
  cpu_context->rcx = (guint64) &ctx->cached_context;
  cpu_context->rdx = (guint64) ctx->user_data;
  cpu_context->r8 = (guint64) ctx->callback;
# else
  cpu_context->rdi = (guint64) &ctx->cached_context;
  cpu_context->rsi = (guint64) ctx->user_data;
  cpu_context->rdx = (guint64) ctx->callback;
# endif

  cpu_context->rsp -= 0x80;
  cpu_context->rsp &= ~0xf;
}
#else
void
gum_process_modify_thread_to_call_function (GumThreadId thread_id,
                                            GumCpuContext * cpu_context,
                                            gpointer user_data)
{
  GumProcessRunOnThreadContext * ctx = (GumProcessRunOnThreadContext *) user_data;

  ctx->cached_context = *cpu_context;

  cpu_context->eip = (guint32) gum_process_call_function_stub;

  cpu_context->esp &= ~0xf;
  cpu_context->esp -= sizeof (gpointer);

  *((gpointer *)cpu_context->esp) = (gpointer)ctx->callback;

  cpu_context->esp -= sizeof (gpointer);
  *((gpointer *)cpu_context->esp) = ctx->user_data;

  cpu_context->esp -= sizeof (gpointer);
  *((gpointer *)cpu_context->esp) = &ctx->cached_context;

  cpu_context->esp -= sizeof (gpointer);
}
#endif

void
gum_process_call_with_full_context (GumCpuContext * cpu_context,
                                    GumProcessFullContextFunc callback,
                                    gpointer user_data)
{
  GumFullCpuContext full_context;

  full_context.regs = *cpu_context;

  gum_process_fxsave (&full_context.fpu);
  if (gum_process_has_avx ())
    gum_process_save_avx (&full_context.avx);

  callback (&full_context, user_data);

  if (gum_process_has_avx())
    gum_process_restore_avx (&full_context.avx);
  gum_process_fxrestore (&full_context.fpu);
}

gboolean
gum_process_has_avx()
{
  GumCpuFeatures features = gum_query_cpu_features();
  if ((features & GUM_CPU_AVX2) == 0)
    return FALSE;;

  return TRUE;
}

#ifndef HAVE_WINDOWS
#if defined (_M_X64) || defined (__x86_64__)
void
gum_process_fxsave (GumX64FpuRegs * regs)
{
  register void * rdi asm ("rdi") = regs;
  // fxsave [rdi]
  asm volatile (
    ".byte 0x0f, 0xae, 0x07\n\t"
    :
    : "r" (rdi)
    : "cc", "memory"
  );
}

void
gum_process_fxrestore (GumX64FpuRegs * regs)
{
  register void * rdi asm ("rdi") = regs;
  // fxrstor [rdi]
  asm volatile (
    ".byte 0x0f, 0xae, 0x0f\n\t"
    :
    : "r" (rdi)
    : "cc", "memory"
  );
}

void
gum_process_save_avx (GumX64AvxRegs * regs)
{
  register void * rdi asm ("rdi") = regs;
  // "vextracti128 xmmword ptr [rdi], ymm0, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x10], ymm1, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x20], ymm2, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x30], ymm3, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x40], ymm4, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x50], ymm5, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x60], ymm6, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x70], ymm7, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x80], ymm8, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0x90], ymm9, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xa0], ymm10, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xb0], ymm11, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xc0], ymm12, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xd0], ymm13, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xe0], ymm14, 1\n\t"
  // "vextracti128 xmmword ptr [rdi + 0xf0], ymm15, 1\n\t"

  asm volatile (
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x07, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x4f, 0x10, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x57, 0x20, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x5f, 0x30, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x67, 0x40, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x6f, 0x50, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x77, 0x60, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x7f, 0x70, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0x87, 0x80, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0x8f, 0x90, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0x97, 0xa0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0x9f, 0xb0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0xa7, 0xc0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0xaf, 0xd0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0xb7, 0xe0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x7d, 0x39, 0xbf, 0xf0, 0x00, 0x00, 0x00, 0x01\n\t"
    :
    : "r" (rdi)
    : "cc", "memory"
  );
}

void
gum_process_restore_avx (GumX64AvxRegs * regs)
{
  register void * rdi asm ("rdi") = regs;

  // "vinserti128 ymm0, ymm0, xmmword ptr [rdi], 1\n\t"
  // "vinserti128 ymm1, ymm1, xmmword ptr [rdi + 0x10], 1\n\t"
  // "vinserti128 ymm2, ymm2, xmmword ptr [rdi + 0x20], 1\n\t"
  // "vinserti128 ymm3, ymm3, xmmword ptr [rdi + 0x30], 1\n\t"
  // "vinserti128 ymm4, ymm4, xmmword ptr [rdi + 0x40], 1\n\t"
  // "vinserti128 ymm5, ymm5, xmmword ptr [rdi + 0x50], 1\n\t"
  // "vinserti128 ymm6, ymm6, xmmword ptr [rdi + 0x60], 1\n\t"
  // "vinserti128 ymm7, ymm7, xmmword ptr [rdi + 0x70], 1\n\t"
  // "vinserti128 ymm8, ymm8, xmmword ptr [rdi + 0x80], 1\n\t"
  // "vinserti128 ymm9, ymm9, xmmword ptr [rdi + 0x90], 1\n\t"
  // "vinserti128 ymm10, ymm10, xmmword ptr [rdi + 0xa0], 1\n\t"
  // "vinserti128 ymm11, ymm11, xmmword ptr [rdi + 0xb0], 1\n\t"
  // "vinserti128 ymm12, ymm12, xmmword ptr [rdi + 0xc0], 1\n\t"
  // "vinserti128 ymm13, ymm13, xmmword ptr [rdi + 0xd0], 1\n\t"
  // "vinserti128 ymm14, ymm14, xmmword ptr [rdi + 0xe0], 1\n\t"
  // "vinserti128 ymm15, ymm15, xmmword ptr [rdi + 0xf0], 1\n\t"
  asm volatile (
    ".byte 0xc4, 0xe3, 0x7d, 0x38, 0x07, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x75, 0x38, 0x4f, 0x10, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x6d, 0x38, 0x57, 0x20, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x65, 0x38, 0x5f, 0x30, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x5d, 0x38, 0x67, 0x40, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x55, 0x38, 0x6f, 0x50, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x4d, 0x38, 0x77, 0x60, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x45, 0x38, 0x7f, 0x70, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x3d, 0x38, 0x87, 0x80, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x35, 0x38, 0x8f, 0x90, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x2d, 0x38, 0x97, 0xa0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x25, 0x38, 0x9f, 0xb0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x1d, 0x38, 0xa7, 0xc0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x15, 0x38, 0xaf, 0xd0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x0d, 0x38, 0xb7, 0xe0, 0x00, 0x00, 0x00, 0x01\n\t"
    ".byte 0xc4, 0x63, 0x05, 0x38, 0xbf, 0xf0, 0x00, 0x00, 0x00, 0x01\n\t"
    :
    : "r" (rdi)
    : "cc", "memory"
  );
}
# else
void
gum_process_fxsave (GumIA32FpuRegs * regs)
{
  register void * edi asm ("edi") = regs;
  // fxsave [edi]
  asm volatile (
    ".byte 0x0f, 0xae, 0x07\n\t"
    :
    : "r" (edi)
    : "cc", "memory"
  );
}

void
gum_process_fxrestore (GumIA32FpuRegs * regs)
{
  register void * edi asm ("edi") = regs;
  // fxrstor [edi]
  asm volatile (
    ".byte 0x0f, 0xae, 0x0f\n\t"
    :
    : "r" (edi)
    : "cc", "memory"
  );
}

void
gum_process_save_avx (GumIA32AvxRegs * regs)
{
  register void * edi asm ("edi") = regs;

  // "vextracti128 xmmword ptr [edi], ymm0, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x10], ymm1, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x20], ymm2, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x30], ymm3, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x40], ymm4, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x50], ymm5, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x60], ymm6, 1\n\t"
  // "vextracti128 xmmword ptr [edi + 0x70], ymm7, 1\n\t"
  asm volatile (
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x07, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x4f, 0x10, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x57, 0x20, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x5f, 0x30, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x67, 0x40, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x6f, 0x50, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x77, 0x60, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x7d, 0x39, 0x7f, 0x70, 0x01\n\t"
    :
    : "r" (edi)
    : "cc", "memory"
  );
}

void
gum_process_restore_avx (GumIA32AvxRegs * regs)
{
  register void * edi asm ("edi") = regs;

  // "vinserti128 ymm0, ymm0, xmmword ptr [edi], 1\n\t"
  // "vinserti128 ymm1, ymm1, xmmword ptr [edi + 0x10], 1\n\t"
  // "vinserti128 ymm2, ymm2, xmmword ptr [edi + 0x20], 1\n\t"
  // "vinserti128 ymm3, ymm3, xmmword ptr [edi + 0x30], 1\n\t"
  // "vinserti128 ymm4, ymm4, xmmword ptr [edi + 0x40], 1\n\t"
  // "vinserti128 ymm5, ymm5, xmmword ptr [edi + 0x50], 1\n\t"
  // "vinserti128 ymm6, ymm6, xmmword ptr [edi + 0x60], 1\n\t"
  // "vinserti128 ymm7, ymm7, xmmword ptr [edi + 0x70], 1\n\t"
  asm volatile (
    ".byte 0xc4, 0xe3, 0x7d, 0x38, 0x07, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x75, 0x38, 0x4f, 0x10, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x6d, 0x38, 0x57, 0x20, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x65, 0x38, 0x5f, 0x30, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x5d, 0x38, 0x67, 0x40, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x55, 0x38, 0x6f, 0x50, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x4d, 0x38, 0x77, 0x60, 0x01\n\t"
    ".byte 0xc4, 0xe3, 0x45, 0x38, 0x7f, 0x70, 0x01\n\t"
    :
    : "r" (edi)
    : "cc", "memory"
  );
}
# endif
#endif
