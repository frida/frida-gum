/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_KERNEL_H__
#define __GUM_SCRIPT_KERNEL_H__

#include "gumscriptcore.h"

typedef struct _GumScriptKernel GumScriptKernel;

struct _GumScriptKernel
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_kernel_init (GumScriptKernel * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_kernel_realize (GumScriptKernel * self);
G_GNUC_INTERNAL void _gum_script_kernel_dispose (GumScriptKernel * self);
G_GNUC_INTERNAL void _gum_script_kernel_finalize (GumScriptKernel * self);

#endif
