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
typedef struct _GumV8InvocationContext GumV8InvocationContext;
typedef struct _GumV8InvocationArgs GumV8InvocationArgs;

struct _GumV8Interceptor
{
  GumV8Core * core;

  GumInterceptor * interceptor;

  GHashTable * invocation_listeners;
  GHashTable * replacement_by_address;
  GSource * flush_timer;

  GumPersistent<v8::Object>::type * invocation_listener_value;
  GumPersistent<v8::Object>::type * invocation_context_value;
  GumPersistent<v8::Object>::type * invocation_args_value;
  GumPersistent<v8::Object>::type * invocation_return_value;

  GumV8InvocationContext * cached_invocation_context;
  gboolean cached_invocation_context_in_use;

  GumV8InvocationArgs * cached_invocation_args;
  gboolean cached_invocation_args_in_use;
};

struct _GumV8InvocationContext
{
  GumPersistent<v8::Object>::type * object;
  GumInvocationContext * handle;
  GumPersistent<v8::Object>::type * cpu_context;

  GumV8Core * core;
};

G_GNUC_INTERNAL void _gum_v8_interceptor_init (GumV8Interceptor * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_interceptor_realize (GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_flush (GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_dispose (GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_finalize (GumV8Interceptor * self);

G_GNUC_INTERNAL GumV8InvocationContext *
    _gum_v8_interceptor_obtain_invocation_context (GumV8Interceptor * self);
G_GNUC_INTERNAL void _gum_v8_interceptor_release_invocation_context (
    GumV8Interceptor * self, GumV8InvocationContext * jic);
G_GNUC_INTERNAL void _gum_v8_invocation_context_reset (
    GumV8InvocationContext * self, GumInvocationContext * handle);

#endif
