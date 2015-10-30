/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_KERNEL_H__
#define __GUM_JSCRIPT_KERNEL_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscKernel GumJscKernel;

struct _GumJscKernel
{
  GumJscCore * core;
};

G_GNUC_INTERNAL void _gum_jsc_kernel_init (GumJscKernel * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_kernel_dispose (GumJscKernel * self);
G_GNUC_INTERNAL void _gum_jsc_kernel_finalize (GumJscKernel * self);

G_END_DECLS

#endif
