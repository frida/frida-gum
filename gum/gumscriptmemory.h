/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_MEMORY_H__
#define __GUM_SCRIPT_MEMORY_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptMemory GumScriptMemory;

struct _GumScriptMemory
{
  GumScriptCore * core;

  GumPersistent<v8::String>::type * length_key;
};

G_GNUC_INTERNAL void _gum_script_memory_init (GumScriptMemory * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_memory_realize (GumScriptMemory * self);
G_GNUC_INTERNAL void _gum_script_memory_dispose (GumScriptMemory * self);
G_GNUC_INTERNAL void _gum_script_memory_finalize (GumScriptMemory * self);

#endif
