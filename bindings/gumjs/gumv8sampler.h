/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SAMPLER_H__
#define __GUM_V8_SAMPLER_H__

#include "gumv8object.h"

struct GumV8Sampler
{
  GumV8Core * core;

  GumV8ObjectManager objects;
};

G_GNUC_INTERNAL void _gum_v8_sampler_init (GumV8Sampler * self,
    GumV8Core * core, v8::Local<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_sampler_realize (GumV8Sampler * self);
G_GNUC_INTERNAL void _gum_v8_sampler_flush (GumV8Sampler * self);
G_GNUC_INTERNAL void _gum_v8_sampler_dispose (GumV8Sampler * self);
G_GNUC_INTERNAL void _gum_v8_sampler_finalize (GumV8Sampler * self);

#endif
