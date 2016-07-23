/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_KERNEL_H__
#define __GUM_DUK_KERNEL_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukKernel GumDukKernel;

struct _GumDukKernel
{
  GumDukCore * core;
};

G_GNUC_INTERNAL void _gum_duk_kernel_init (GumDukKernel * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_kernel_dispose (GumDukKernel * self);
G_GNUC_INTERNAL void _gum_duk_kernel_finalize (GumDukKernel * self);

G_END_DECLS

#endif
