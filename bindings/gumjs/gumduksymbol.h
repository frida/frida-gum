/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_SYMBOL_H__
#define __GUM_DUKRIPT_SYMBOL_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukSymbol GumDukSymbol;

struct _GumDukSymbol
{
  GumDukCore * core;

  GumDukHeapPtr symbol;
};

G_GNUC_INTERNAL void _gum_duk_symbol_init (GumDukSymbol * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_symbol_dispose (GumDukSymbol * self);
G_GNUC_INTERNAL void _gum_duk_symbol_finalize (GumDukSymbol * self);

G_END_DECLS

#endif
