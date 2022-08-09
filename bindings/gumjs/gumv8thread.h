/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_THREAD_H__
#define __GUM_V8_THREAD_H__

#include "gumv8core.h"

#include <gum/gumbacktracer.h>

struct GumV8Thread
{
  GumV8Core * core;

  GumBacktracer * accurate_backtracer;
  GumBacktracer * fuzzy_backtracer;

  v8::Global<v8::Symbol> * accurate_enum_value;
  v8::Global<v8::Symbol> * fuzzy_enum_value;
};

G_GNUC_INTERNAL void _gum_v8_thread_init (GumV8Thread * self,
    GumV8Core * core, v8::Local<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_thread_realize (GumV8Thread * self);
G_GNUC_INTERNAL void _gum_v8_thread_dispose (GumV8Thread * self);
G_GNUC_INTERNAL void _gum_v8_thread_finalize (GumV8Thread * self);

#endif
