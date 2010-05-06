/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumwindowsbacktracer.h"
#include "gumdbghelp.h"

static void gum_windows_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_windows_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumWindowsBacktracer,
                        gum_windows_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_windows_backtracer_iface_init));

static void gum_windows_backtracer_fill_address_details (
    GumWindowsBacktracer * self, GumReturnAddress * ret_addr);

static GumDbgHelpImpl * dbghelp = NULL;

static void
gum_windows_backtracer_class_init (GumWindowsBacktracerClass * klass)
{
  dbghelp = gum_dbghelp_impl_obtain ();
}

static void
gum_windows_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_windows_backtracer_generate;
}

static void
gum_windows_backtracer_init (GumWindowsBacktracer * self)
{
}

GumBacktracer *
gum_windows_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_WINDOWS_BACKTRACER, NULL);
}

static void
gum_windows_backtracer_generate (GumBacktracer * backtracer,
                                 const GumCpuContext * cpu_context,
                                 GumReturnAddressArray * return_addresses)
{
  GumWindowsBacktracer * self = GUM_WINDOWS_BACKTRACER_CAST (backtracer);
  guint i;
  guint skip_count = 0;
  STACKFRAME64 frame = { 0, };
  CONTEXT context = { 0, };
  BOOL success;

  /* Get the raw addresses */
  RtlCaptureContext (&context);

  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Mode = AddrModeFlat;

  if (cpu_context != NULL)
  {
#ifndef _WIN64
    context.Eip = cpu_context->eip;
    context.Edi = cpu_context->edi;
    context.Esi = cpu_context->esi;
    context.Ebp = cpu_context->ebp;
    context.Esp = cpu_context->esp;
    context.Ebx = cpu_context->ebx;
    context.Edx = cpu_context->edx;
    context.Ecx = cpu_context->ecx;
    context.Eax = cpu_context->eax;
#endif

#if GLIB_SIZEOF_VOID_P == 8
    frame.AddrPC.Offset = cpu_context->rip;
    frame.AddrFrame.Offset = cpu_context->rbp;
    frame.AddrStack.Offset = cpu_context->rsp;
#else
    frame.AddrPC.Offset = cpu_context->eip;
    frame.AddrFrame.Offset = cpu_context->ebp;
    frame.AddrStack.Offset = cpu_context->esp;
#endif
  }
  else
  {
#ifndef _WIN64
    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrStack.Offset = context.Esp;
#endif

#ifdef _DEBUG
    skip_count = 1; /* leave out this function */
#endif
  }

  dbghelp->Lock ();

  for (i = 0; i < GUM_MAX_BACKTRACE_DEPTH + skip_count; i++)
  {
    success = dbghelp->StackWalk64 (IMAGE_FILE_MACHINE_I386,
        GetCurrentProcess (), GetCurrentThread (), &frame, &context, NULL,
        dbghelp->SymFunctionTableAccess64, dbghelp->SymGetModuleBase64, NULL);
    if (!success)
      break;
    else if (frame.AddrPC.Offset == frame.AddrReturn.Offset)
      break;
    else if (frame.AddrPC.Offset != 0)
    {
      if (i >= skip_count)
      {
        GumReturnAddress * ret_addr;

        ret_addr = &return_addresses->items[return_addresses->len++];
        memset (ret_addr, 0, sizeof (GumReturnAddress));
        ret_addr->address = (gpointer) frame.AddrPC.Offset;
      }
    }
  }

  dbghelp->Unlock ();
}
