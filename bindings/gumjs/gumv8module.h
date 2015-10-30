/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_MODULE_H__
#define __GUM_SCRIPT_MODULE_H__

#include "gumv8core.h"

#include <v8.h>

typedef struct _GumV8Module GumV8Module;

struct _GumV8Module
{
  GumV8Core * core;
};

G_GNUC_INTERNAL void _gum_v8_module_init (GumV8Module * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_module_realize (GumV8Module * self);
G_GNUC_INTERNAL void _gum_v8_module_dispose (GumV8Module * self);
G_GNUC_INTERNAL void _gum_v8_module_finalize (GumV8Module * self);

#endif
