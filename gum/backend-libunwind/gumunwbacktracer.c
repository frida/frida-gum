/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumunwbacktracer.h"

#include "guminterceptor.h"

#define UNW_LOCAL_ONLY
#include <libunwind.h>

static void gum_unw_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_unw_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

static void gum_cpu_context_to_unw (const GumCpuContext * ctx,
    unw_context_t * uc);

G_DEFINE_TYPE_EXTENDED (GumUnwBacktracer,
                        gum_unw_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_unw_backtracer_iface_init));

static void
gum_unw_backtracer_class_init (GumUnwBacktracerClass * klass)
{
}

static void
gum_unw_backtracer_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_unw_backtracer_generate;
}

static void
gum_unw_backtracer_init (GumUnwBacktracer * self)
{
}

GumBacktracer *
gum_unw_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_UNW_BACKTRACER, NULL);
}

static void
gum_unw_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses)
{
  unw_context_t context;
  unw_cursor_t cursor;
  guint start_index, i;
  GumInvocationStack * invocation_stack;

  if (cpu_context != NULL)
  {
#if defined (HAVE_I386)
    return_addresses->items[0] =
        GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64) || defined (HAVE_MIPS)
    return_addresses->items[0] = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif
    start_index = 1;

    gum_cpu_context_to_unw (cpu_context, &context);
  }
  else
  {
    start_index = 0;

#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Winline-asm"
#endif
    unw_getcontext (&context);
#ifdef __clang__
# pragma clang diagnostic pop
#endif
  }

  unw_init_local (&cursor, &context);
  for (i = start_index;
      i < G_N_ELEMENTS (return_addresses->items) && unw_step (&cursor) > 0;
      i++)
  {
    unw_word_t pc;

    unw_get_reg (&cursor, UNW_REG_IP, &pc);
    return_addresses->items[i] = GSIZE_TO_POINTER (pc);
  }
  return_addresses->len = i;

  invocation_stack = gum_interceptor_get_current_stack ();
  for (i = 0; i != return_addresses->len; i++)
  {
    return_addresses->items[i] = gum_invocation_stack_translate (
        invocation_stack, return_addresses->items[i]);
  }
}

static void
gum_cpu_context_to_unw (const GumCpuContext * ctx,
                        unw_context_t * uc)
{
#if defined (UNW_TARGET_X86)
# if defined (HAVE_QNX)
  X86_CPU_REGISTERS * regs = &uc->uc_mcontext.cpu;
# else
  greg_t * gr = uc->uc_mcontext.gregs;
# endif

  unw_getcontext (uc);

# if defined (HAVE_QNX)
  regs->eip = ctx->eip;

  regs->edi = ctx->edi;
  regs->esi = ctx->esi;
  regs->ebp = ctx->ebp;
  regs->esp = ctx->esp;
  regs->ebx = ctx->ebx;
  regs->edx = ctx->edx;
  regs->ecx = ctx->ecx;
  regs->eax = ctx->eax;
# else
  gr[REG_EIP] = ctx->eip;

  gr[REG_EDI] = ctx->edi;
  gr[REG_ESI] = ctx->esi;
  gr[REG_EBP] = ctx->ebp;
  gr[REG_ESP] = ctx->esp;
  gr[REG_EBX] = ctx->ebx;
  gr[REG_EDX] = ctx->edx;
  gr[REG_ECX] = ctx->ecx;
  gr[REG_EAX] = ctx->eax;
# endif
#elif defined (UNW_TARGET_X86_64)
  greg_t * gr = uc->uc_mcontext.gregs;

  unw_getcontext (uc);

  gr[REG_RIP] = ctx->rip;

  gr[REG_R15] = ctx->r15;
  gr[REG_R14] = ctx->r14;
  gr[REG_R13] = ctx->r13;
  gr[REG_R12] = ctx->r12;
  gr[REG_R11] = ctx->r11;
  gr[REG_R10] = ctx->r10;
  gr[REG_R9] = ctx->r9;
  gr[REG_R8] = ctx->r8;

  gr[REG_RDI] = ctx->rdi;
  gr[REG_RSI] = ctx->rsi;
  gr[REG_RBP] = ctx->rbp;
  gr[REG_RSP] = ctx->rsp;
  gr[REG_RBX] = ctx->rbx;
  gr[REG_RDX] = ctx->rdx;
  gr[REG_RCX] = ctx->rcx;
  gr[REG_RAX] = ctx->rax;
#elif defined (UNW_TARGET_ARM)
  uc->regs[UNW_ARM_R15] = ctx->pc;
  uc->regs[UNW_ARM_R13] = ctx->sp;

  {
    guint i;

    for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
      uc->regs[i] = ctx->r[i];
  }

  uc->regs[UNW_ARM_R14] = ctx->lr;
#elif defined (UNW_TARGET_AARCH64)
  mcontext_t * mc = &uc->uc_mcontext;

  unw_getcontext (uc);

  mc->pc = ctx->pc - 4;
  mc->sp = ctx->sp;

  memcpy (mc->regs, ctx->x, sizeof (ctx->x));
  mc->regs[29] = ctx->fp;
  mc->regs[30] = ctx->lr;
#elif defined (UNW_TARGET_MIPS)
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[1] = ctx->at;

  gr[2] = ctx->v0;
  gr[3] = ctx->v1;

  gr[4] = ctx->a0;
  gr[5] = ctx->a1;
  gr[6] = ctx->a2;
  gr[7] = ctx->a3;

  gr[8] = ctx->t0;
  gr[9] = ctx->t1;
  gr[10] = ctx->t2;
  gr[11] = ctx->t3;
  gr[12] = ctx->t4;
  gr[13] = ctx->t5;
  gr[14] = ctx->t6;
  gr[15] = ctx->t7;

  gr[16] = ctx->s0;
  gr[17] = ctx->s1;
  gr[18] = ctx->s2;
  gr[19] = ctx->s3;
  gr[20] = ctx->s4;
  gr[21] = ctx->s5;
  gr[22] = ctx->s6;
  gr[23] = ctx->s7;

  gr[24] = ctx->t8;
  gr[25] = ctx->t9;

  gr[26] = ctx->k0;
  gr[27] = ctx->k1;

  gr[28] = ctx->gp;
  gr[29] = ctx->sp;
  gr[30] = ctx->fp;
  gr[31] = ctx->ra;

  uc->uc_mcontext.mdhi = ctx->hi;
  uc->uc_mcontext.mdlo = ctx->lo;

  uc->uc_mcontext.pc = ctx->pc;
#else
# error FIXME
#endif
}

