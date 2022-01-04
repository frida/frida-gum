/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
  __declspec (align (64)) CONTEXT context = { 0, };
#if GLIB_SIZEOF_VOID_P == 4
  __declspec (align (64)) CONTEXT context_next = { 0, };
#endif
  STACKFRAME64 frame = { 0, };
  gboolean has_ffi_frames = FALSE;
  guint skip_count = 0;
  HANDLE current_process, current_thread;
  GumInvocationStack * invocation_stack;
  guint depth, i;
  BOOL success;

  self = GUM_DBGHELP_BACKTRACER (backtracer);
  dbghelp = self->dbghelp;

  /* Get the raw addresses */
  RtlCaptureContext (&context);

  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Mode = AddrModeFlat;

  if (cpu_context != NULL)
  {
#if GLIB_SIZEOF_VOID_P == 4
    context.Eip = cpu_context->eip;

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
    context.Rip = cpu_context->rip;

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
      skip_count += 2;
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

    skip_count++; /* leave out this function */
  }

  return_addresses->len = 0;

  current_process = GetCurrentProcess ();
  current_thread = GetCurrentThread ();

  invocation_stack = gum_interceptor_get_current_stack ();

  dbghelp->Lock ();

  depth = MIN (limit, GUM_MAX_BACKTRACE_DEPTH);

  for (i = 0; i < depth + skip_count; i++)
  {
#if GLIB_SIZEOF_VOID_P == 4
    if (has_ffi_frames)
    {
      if (i == 2)
      {
        context_next = context;
        context.Ebp = context.Esp + GUM_FFI_STACK_SKIP - 4;
      }
      else if (i == 3)
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
    else if (frame.AddrPC.Offset == frame.AddrReturn.Offset)
      continue;
    else if (frame.AddrPC.Offset != 0)
    {
      if (i >= skip_count)
      {
        gpointer pc, translated_pc;

        g_assert (return_addresses->len <
            G_N_ELEMENTS (return_addresses->items));

        pc = GSIZE_TO_POINTER (frame.AddrPC.Offset);
        translated_pc = gum_invocation_stack_translate (invocation_stack, pc);
        if (translated_pc != pc)
        {
#if GLIB_SIZEOF_VOID_P == 4
          context.Eip = GPOINTER_TO_SIZE (translated_pc);
#else
          context.Rip = GPOINTER_TO_SIZE (translated_pc);
#endif
          frame.AddrPC.Offset = GPOINTER_TO_SIZE (translated_pc);
        }

        return_addresses->items[return_addresses->len++] =
            GSIZE_TO_POINTER (frame.AddrPC.Offset);
      }
    }
  }

  dbghelp->Unlock ();

  if (return_addresses->len >= 2)
  {
    for (i = 1; i != return_addresses->len; i++)
      return_addresses->items[i - 1] = return_addresses->items[i];
  }

  if (return_addresses->len >= 1)
    return_addresses->len--;
}

#endif
