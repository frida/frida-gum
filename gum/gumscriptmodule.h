/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_MODULE_H__
#define __GUM_SCRIPT_MODULE_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptModule GumScriptModule;

struct _GumScriptModule
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_module_init (GumScriptModule * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_module_realize (GumScriptModule * self);
G_GNUC_INTERNAL void _gum_script_module_dispose (GumScriptModule * self);
G_GNUC_INTERNAL void _gum_script_module_finalize (GumScriptModule * self);

#endif
