/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MODULE_H__
#define __GUM_JSCRIPT_MODULE_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscModule GumJscModule;

struct _GumJscModule
{
  GumJscCore * core;

  JSClassRef module_import;
  JSClassRef module_export;
};

G_GNUC_INTERNAL void _gum_jsc_module_init (GumJscModule * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_module_dispose (GumJscModule * self);
G_GNUC_INTERNAL void _gum_jsc_module_finalize (GumJscModule * self);

G_END_DECLS

#endif
