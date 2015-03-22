/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SYMBOL_H__
#define __GUM_SCRIPT_SYMBOL_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptSymbol GumScriptSymbol;

struct _GumScriptSymbol
{
  GumScriptCore * core;

  GHashTable * symbols;

  GumPersistent<v8::Object>::type * value;
};

G_GNUC_INTERNAL void _gum_script_symbol_init (GumScriptSymbol * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_symbol_realize (GumScriptSymbol * self);
G_GNUC_INTERNAL void _gum_script_symbol_dispose (GumScriptSymbol * self);
G_GNUC_INTERNAL void _gum_script_symbol_finalize (GumScriptSymbol * self);

#endif
