/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumgccbacktracer.h"

#include <unwind.h>

typedef struct _GumGccBacktraceCtx GumGccBacktraceCtx;

struct _GumGccBacktraceCtx
{
  GumReturnAddressArray * return_addresses;
  gpointer start_address;
};

static void gum_gcc_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_gcc_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);
static _Unwind_Reason_Code gum_gcc_backtracer_append_address (
    struct _Unwind_Context * context, void * user_data);

G_DEFINE_TYPE_EXTENDED (GumGccBacktracer,
                        gum_gcc_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_gcc_backtracer_iface_init));

static void
gum_gcc_backtracer_class_init (GumGccBacktracerClass * klass)
{
}

static void
gum_gcc_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_gcc_backtracer_generate;
}

static void
gum_gcc_backtracer_init (GumGccBacktracer * self)
{
}

GumBacktracer *
gum_gcc_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_GCC_BACKTRACER, NULL);
}

static void
gum_gcc_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses)
{
  GumGccBacktraceCtx btctx;

  btctx.return_addresses = return_addresses;
  if (cpu_context != NULL)
  {
#ifdef HAVE_I386
    btctx.start_address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XSP (cpu_context));
#else
    btctx.start_address = GSIZE_TO_POINTER (cpu_context->sp);
#endif
  }
  else
  {
    btctx.start_address = ((gsize *) &return_addresses) + 1;
  }

  return_addresses->len = 0;
  _Unwind_Backtrace (gum_gcc_backtracer_append_address, &btctx);
}

static _Unwind_Reason_Code
gum_gcc_backtracer_append_address (struct _Unwind_Context * context,
                                   void * user_data)
{
  GumGccBacktraceCtx * btctx = (GumGccBacktraceCtx *) user_data;
  GumReturnAddressArray * arr = btctx->return_addresses;

  if (GSIZE_TO_POINTER (_Unwind_GetGR (context, 7)) < btctx->start_address)
    return _URC_NO_REASON;

  if (arr->len == G_N_ELEMENTS (arr->items))
    return _URC_NORMAL_STOP;

  arr->items[arr->len++] = GSIZE_TO_POINTER (_Unwind_GetIP (context));
  return _URC_NO_REASON;
}
