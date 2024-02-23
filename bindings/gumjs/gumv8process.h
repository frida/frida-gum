/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_PROCESS_H__
#define __GUM_V8_PROCESS_H__

#include "gumv8core.h"
#include "gumv8module.h"

struct GumV8ExceptionHandler;

struct GumV8Process
{
  GumV8Module * module;
  GumV8Core * core;

  v8::Global<v8::Object> * main_module_value;

  GumStalker * stalker;
  GSource * stalker_gc_timer;

  GumV8ExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_v8_process_init (GumV8Process * self,
    GumV8Module * module, GumV8Core * core,
    v8::Local<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_process_realize (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_flush (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_dispose (GumV8Process * self);
G_GNUC_INTERNAL void _gum_v8_process_finalize (GumV8Process * self);

#endif
