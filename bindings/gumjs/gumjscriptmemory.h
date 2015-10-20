/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_MEMORY_H__
#define __GUM_JSCRIPT_MEMORY_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptMemory GumScriptMemory;

struct _GumScriptMemory
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_memory_init (GumScriptMemory * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_memory_dispose (GumScriptMemory * self);
G_GNUC_INTERNAL void _gum_script_memory_finalize (GumScriptMemory * self);

G_END_DECLS

#endif
