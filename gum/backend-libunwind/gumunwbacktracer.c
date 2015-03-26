/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumunwbacktracer.h"

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
  guint i;

  if (cpu_context != NULL)
    gum_cpu_context_to_unw (cpu_context, &context);
  else
    unw_getcontext (&context);

  unw_init_local (&cursor, &context);
  for (i = 0;
      i != G_N_ELEMENTS (return_addresses->items) && unw_step (&cursor) > 0;
      i++)
  {
    unw_word_t pc;

    unw_get_reg (&cursor, UNW_REG_IP, &pc);
    return_addresses->items[i] = GSIZE_TO_POINTER (pc);
  }

  return_addresses->len = i;
}

static void
gum_cpu_context_to_unw (const GumCpuContext * ctx,
                        unw_context_t * uc)
{
#if defined (UNW_TARGET_X86)
  greg_t * gr = uc->uc_mcontext.gregs;

  unw_getcontext (uc);

  gr[REG_EIP] = ctx->eip;

  gr[REG_EDI] = ctx->edi;
  gr[REG_ESI] = ctx->esi;
  gr[REG_EBP] = ctx->ebp;
  gr[REG_ESP] = ctx->esp;
  gr[REG_EBX] = ctx->ebx;
  gr[REG_EDX] = ctx->edx;
  gr[REG_ECX] = ctx->ecx;
  gr[REG_EAX] = ctx->eax;
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

  for (guint i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    uc->regs[i] = ctx->r[i];
  uc->regs[UNW_ARM_R14] = ctx->lr;
#elif defined (UNW_TARGET_AARCH64)
  mcontext_t * mc = &uc->uc_mcontext;

  unw_getcontext (uc);

  mc->pc = ctx->pc;
  mc->sp = ctx->sp;

  memcpy (mc->regs, ctx->x, sizeof (ctx->x));
  mc->regs[29] = ctx->fp;
  mc->regs[30] = ctx->lr;
#else
# error FIXME
#endif
}

