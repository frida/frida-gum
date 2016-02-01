/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_API_RESOLVER_H__
#define __GUM_V8_API_RESOLVER_H__

#include "gumv8core.h"

#include <v8.h>

typedef struct _GumV8ApiResolver GumV8ApiResolver;

struct _GumV8ApiResolver
{
  GumV8Core * core;

  GHashTable * resolvers;
};

G_GNUC_INTERNAL void _gum_v8_api_resolver_init (GumV8ApiResolver * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_api_resolver_realize (GumV8ApiResolver * self);
G_GNUC_INTERNAL void _gum_v8_api_resolver_dispose (GumV8ApiResolver * self);
G_GNUC_INTERNAL void _gum_v8_api_resolver_finalize (GumV8ApiResolver * self);

#endif
