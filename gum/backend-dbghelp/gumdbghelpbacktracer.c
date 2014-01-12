/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumdbghelpbacktracer.h"

#include "gumdbghelp.h"

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_I386
#else
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#endif

struct _GumDbghelpBacktracerPrivate
{
  GumDbgHelpImpl * dbghelp;
};

static void gum_dbghelp_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumDbghelpBacktracer,
                        gum_dbghelp_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_dbghelp_backtracer_iface_init));

static void gum_dbghelp_backtracer_finalize (GObject * object);

static void gum_dbghelp_backtracer_fill_address_details (
    GumDbghelpBacktracer * self, GumReturnAddress * ret_addr);

static void
gum_dbghelp_backtracer_class_init (GumDbghelpBacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumDbghelpBacktracerPrivate));

  object_class->finalize = gum_dbghelp_backtracer_finalize;
}

static void
gum_dbghelp_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  (void) iface_data;

  iface->generate = gum_dbghelp_backtracer_generate;
}

static void
gum_dbghelp_backtracer_init (GumDbghelpBacktracer * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
        GUM_TYPE_DBGHELP_BACKTRACER, GumDbghelpBacktracerPrivate);

  self->priv->dbghelp = gum_dbghelp_impl_obtain ();
}

static void
gum_dbghelp_backtracer_finalize (GObject * object)
{
  GumDbghelpBacktracer * self = GUM_DBGHELP_BACKTRACER (object);

  gum_dbghelp_impl_release (self->priv->dbghelp);

  G_OBJECT_CLASS (gum_dbghelp_backtracer_parent_class)->finalize (object);
}

GumBacktracer *
gum_dbghelp_backtracer_new (void)
{
  return GUM_BACKTRACER_CAST (
      g_object_new (GUM_TYPE_DBGHELP_BACKTRACER, NULL));
}

static void
gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
                                 const GumCpuContext * cpu_context,
                                 GumReturnAddressArray * return_addresses)
{
  GumDbghelpBacktracer * self = GUM_DBGHELP_BACKTRACER_CAST (backtracer);
  GumDbgHelpImpl * dbghelp = self->priv->dbghelp;
  guint i;
  guint skip_count = 0;
  STACKFRAME64 frame = { 0, };
  __declspec (align (64)) CONTEXT context = { 0, };
  BOOL success;

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
#if GLIB_SIZEOF_VOID_P == 4
    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrStack.Offset = context.Esp;
#else
    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrStack.Offset = context.Rsp;
#endif

#ifdef _DEBUG
    skip_count = 1; /* leave out this function */
#endif
#if GLIB_SIZEOF_VOID_P == 8
    skip_count++;
#endif
  }

  return_addresses->len = 0;

  dbghelp->Lock ();

  for (i = 0; i < GUM_MAX_BACKTRACE_DEPTH + skip_count; i++)
  {
    success = dbghelp->StackWalk64 (GUM_BACKTRACER_MACHINE_TYPE,
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
        g_assert_cmpuint (return_addresses->len, <,
            G_N_ELEMENTS (return_addresses->items));
        return_addresses->items[return_addresses->len++] =
            GSIZE_TO_POINTER (frame.AddrPC.Offset);
      }
    }
  }

  dbghelp->Unlock ();
}
