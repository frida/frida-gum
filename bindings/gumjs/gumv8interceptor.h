/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_INTERCEPTOR_H__
#define __GUM_V8_INTERCEPTOR_H__

#include "gumv8core.h"

#include <gum/guminterceptor.h>
#include <v8.h>

typedef struct _GumV8Interceptor GumV8Interceptor;

struct _GumV8Interceptor
{
  GumV8Core * core;

  GumInterceptor * interceptor;

  GQueue * attach_entries;
  GHashTable * replacement_by_address;

  GumPersistent<v8::Object>::type * invocation_context_value;
  GumPersistent<v8::Object>::type * invocation_args_value;
  GumPersistent<v8::Object>::type * invocation_return_value;
};

G_GNUC_INTERNAL void _gum_v8_interceptor_init (GumV8Interceptor * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_interceptor_realize (
    GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_dispose (
    GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_finalize (
    GumV8Interceptor * self);

G_GNUC_INTERNAL void _gum_v8_interceptor_on_enter (
    GumV8Interceptor * self, GumInvocationContext * context);
G_GNUC_INTERNAL void _gum_v8_interceptor_on_leave (
    GumV8Interceptor * self, GumInvocationContext * context);

#endif
