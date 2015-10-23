/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_SYMBOL_H__
#define __GUM_JSCRIPT_SYMBOL_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptSymbol GumScriptSymbol;

struct _GumScriptSymbol
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_symbol_init (GumScriptSymbol * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_symbol_dispose (GumScriptSymbol * self);
G_GNUC_INTERNAL void _gum_script_symbol_finalize (GumScriptSymbol * self);

G_END_DECLS

#endif
