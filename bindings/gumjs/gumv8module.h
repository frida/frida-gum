/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_MODULE_H__
#define __GUM_V8_MODULE_H__

#include "gumv8core.h"

struct GumV8Module
{
  GumV8Core * core;

  GumPersistent<v8::Object>::type * import_value;
  GumPersistent<v8::Object>::type * export_value;

  GumPersistent<v8::String>::type * type_key;
  GumPersistent<v8::String>::type * name_key;
  GumPersistent<v8::String>::type * module_key;
  GumPersistent<v8::String>::type * address_key;
  GumPersistent<v8::String>::type * variable_value;
};

G_GNUC_INTERNAL void _gum_v8_module_init (GumV8Module * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_module_realize (GumV8Module * self);
G_GNUC_INTERNAL void _gum_v8_module_dispose (GumV8Module * self);
G_GNUC_INTERNAL void _gum_v8_module_finalize (GumV8Module * self);

#endif
