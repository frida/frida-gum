/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_PROCESS_H__
#define __GUM_V8_PROCESS_H__

#include "gumv8core.h"

struct GumV8ExceptionHandler;

struct GumV8Process
{
  GumV8Core * core;

  GumV8ExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_v8_process_init (GumV8Process * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_process_realize (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_flush (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_dispose (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_finalize (GumV8Process * self);

#endif
