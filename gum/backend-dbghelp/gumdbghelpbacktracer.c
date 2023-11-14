/*
 * Copyright (C) 2008-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumdbghelpbacktracer.h"

#include "guminterceptor.h"

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_I386
# define GUM_FFI_STACK_SKIP 44
#else
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#endif

#ifdef _MSC_VER
# define GUM_ALIGNED(n) __declspec (align (n))
#else
# define GUM_ALIGNED(n) __attribute__ ((aligned (n)))
#endif

struct _GumDbghelpBacktracer
{
  GObject parent;

  GumDbghelpImpl * dbghelp;
};

static void gum_dbghelp_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context, GumReturnAddressArray * return_addresses,
    guint limit);

G_DEFINE_TYPE_EXTENDED (GumDbghelpBacktracer,
                        gum_dbghelp_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                            gum_dbghelp_backtracer_iface_init))

static void
gum_dbghelp_backtracer_class_init (GumDbghelpBacktracerClass * klass)
{
}

static void
gum_dbghelp_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerInterface * iface = g_iface;

  iface->generate = gum_dbghelp_backtracer_generate;
}

static void
gum_dbghelp_backtracer_init (GumDbghelpBacktracer * self)
{
}

GumBacktracer *
gum_dbghelp_backtracer_new (GumDbghelpImpl * dbghelp)
{
  GumDbghelpBacktracer * backtracer;

  g_assert (dbghelp != NULL);

  backtracer = g_object_new (GUM_TYPE_DBGHELP_BACKTRACER, NULL);
  backtracer->dbghelp = dbghelp;

  return GUM_BACKTRACER (backtracer);
}

static void
gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
                                 const GumCpuContext * cpu_context,
                                 GumReturnAddressArray * return_addresses,
                                 guint limit)
{
  GumDbghelpBacktracer * self;
  GumDbghelpImpl * dbghelp;
  GumInvocationStack * invocation_stack;
  GUM_ALIGNED (64) CONTEXT context = { 0, };
#if GLIB_SIZEOF_VOID_P == 4
  GUM_ALIGNED (64) CONTEXT context_next = { 0, };
#endif
  STACKFRAME64 frame = { 0, };
  gboolean has_ffi_frames;
  gint start_index, n_skip, depth, i;
  HANDLE current_process, current_thread;

  self = GUM_DBGHELP_BACKTRACER (backtracer);
  dbghelp = self->dbghelp;
  invocation_stack = gum_interceptor_get_current_stack ();

  /* Get the raw addresses */
  RtlCaptureContext (&context);

  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Mode = AddrModeFlat;

  if (cpu_context != NULL)
  {
#if GLIB_SIZEOF_VOID_P == 4
    if (cpu_context->eip != 0)
      context.Eip = cpu_context->eip;
    else
      context.Eip = *((gsize *) GSIZE_TO_POINTER (cpu_context->esp));

    context.Edi = cpu_context->edi;
    context.Esi = cpu_context->esi;
    context.Ebp = cpu_context->ebp;
    context.Esp = cpu_context->esp;
    context.Ebx = cpu_context->ebx;
    context.Edx = cpu_context->edx;
    context.Ecx = cpu_context->ecx;
    context.Eax = cpu_context->eax;

    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = cpu_context->ebp;
    frame.AddrStack.Offset = cpu_context->esp;
#else
    if (cpu_context->rip != 0)
      context.Rip = cpu_context->rip;
    else
      context.Rip = *((gsize *) GSIZE_TO_POINTER (cpu_context->rsp));

    context.R15 = cpu_context->r15;
    context.R14 = cpu_context->r14;
    context.R13 = cpu_context->r13;
    context.R12 = cpu_context->r12;
    context.R11 = cpu_context->r11;
    context.R10 = cpu_context->r10;
    context.R9  = cpu_context->r9;
    context.R8  = cpu_context->r8;

    context.Rdi = cpu_context->rdi;
    context.Rsi = cpu_context->rsi;
    context.Rbp = cpu_context->rbp;
    context.Rsp = cpu_context->rsp;
    context.Rbx = cpu_context->rbx;
    context.Rdx = cpu_context->rdx;
    context.Rcx = cpu_context->rcx;
    context.Rax = cpu_context->rax;

    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = cpu_context->rsp;
    frame.AddrStack.Offset = cpu_context->rsp;
#endif

    has_ffi_frames = GUM_CPU_CONTEXT_XIP (cpu_context) == 0;
    if (has_ffi_frames)
    {
      start_index = 0;
      n_skip = 2;
    }
    else
    {
#if GLIB_SIZEOF_VOID_P == 4
      return_addresses->items[0] = gum_invocation_stack_translate (
          invocation_stack, *((GumReturnAddress *) GSIZE_TO_POINTER (
              GUM_CPU_CONTEXT_XSP (cpu_context))));
      start_index = 1;
      n_skip = 0;
#else
      start_index = 0;
      n_skip = 1;
#endif
    }
  }
  else
  {
#if GLIB_SIZEOF_VOID_P == 4
    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrStack.Offset = context.Esp;
#else
    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = context.Rsp;
    frame.AddrStack.Offset = context.Rsp;
#endif

    start_index = 0;
    n_skip = 1; /* Leave out this function. */
    has_ffi_frames = FALSE;
  }

  current_process = GetCurrentProcess ();
  current_thread = GetCurrentThread ();

  depth = MIN (limit, G_N_ELEMENTS (return_addresses->items));

  dbghelp->Lock ();

  for (i = start_index; i < depth; i++)
  {
    BOOL success;
    gpointer pc, translated_pc;

#if GLIB_SIZEOF_VOID_P == 4
    if (has_ffi_frames && n_skip == 0)
    {
      if (i == 0)
      {
        context_next = context;
        context.Ebp = context.Esp + GUM_FFI_STACK_SKIP - 4;
      }
      else if (i == 1)
      {
        context = context_next;
      }
    }
#endif

    success = dbghelp->StackWalk64 (GUM_BACKTRACER_MACHINE_TYPE,
        current_process, current_thread, &frame, &context, NULL,
        dbghelp->SymFunctionTableAccess64, dbghelp->SymGetModuleBase64, NULL);
    if (!success)
      break;
    if (frame.AddrPC.Offset == frame.AddrReturn.Offset)
      continue;
    if (frame.AddrPC.Offset == 0)
      continue;

    pc = GSIZE_TO_POINTER (frame.AddrPC.Offset);
    translated_pc = gum_invocation_stack_translate (invocation_stack, pc);

    return_addresses->items[i] = translated_pc;

    if (translated_pc != pc)
    {
#if GLIB_SIZEOF_VOID_P == 4
      context.Eip = GPOINTER_TO_SIZE (translated_pc);
#else
      context.Rip = GPOINTER_TO_SIZE (translated_pc);
#endif
      frame.AddrPC.Offset = GPOINTER_TO_SIZE (translated_pc);
    }

    if (n_skip > 0)
    {
      n_skip--;
      i--;
    }
  }
  return_addresses->len = i;

  dbghelp->Unlock ();
}

#endif
