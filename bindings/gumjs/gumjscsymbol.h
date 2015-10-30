/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_SYMBOL_H__
#define __GUM_JSCRIPT_SYMBOL_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscSymbol GumJscSymbol;

struct _GumJscSymbol
{
  GumJscCore * core;

  JSClassRef symbol;
};

G_GNUC_INTERNAL void _gum_jsc_symbol_init (GumJscSymbol * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_symbol_dispose (GumJscSymbol * self);
G_GNUC_INTERNAL void _gum_jsc_symbol_finalize (GumJscSymbol * self);

G_END_DECLS

#endif
