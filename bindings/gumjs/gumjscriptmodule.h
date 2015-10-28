/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MODULE_H__
#define __GUM_JSCRIPT_MODULE_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptModule GumScriptModule;

struct _GumScriptModule
{
  GumScriptCore * core;

  JSClassRef module_export;
};

G_GNUC_INTERNAL void _gum_script_module_init (GumScriptModule * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_module_dispose (GumScriptModule * self);
G_GNUC_INTERNAL void _gum_script_module_finalize (GumScriptModule * self);

G_END_DECLS

#endif
