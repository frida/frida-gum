/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_INTERCEPTOR_H__
#define __GUM_SCRIPT_INTERCEPTOR_H__

#include "gumscriptcore.h"

#include <gum/guminterceptor.h>
#include <v8.h>

typedef struct _GumScriptInterceptor GumScriptInterceptor;

struct _GumScriptInterceptor
{
  GumScriptCore * core;

  GumInterceptor * interceptor;

  GQueue * attach_entries;
  GHashTable * replacement_by_address;

  GumPersistent<v8::Object>::type * invocation_context_value;
  GumPersistent<v8::Object>::type * invocation_args_value;
  GumPersistent<v8::Object>::type * invocation_return_value;
};

G_GNUC_INTERNAL void _gum_script_interceptor_init (GumScriptInterceptor * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_interceptor_realize (
    GumScriptInterceptor * self);
G_GNUC_INTERNAL void _gum_script_interceptor_dispose (
    GumScriptInterceptor * self);
G_GNUC_INTERNAL void _gum_script_interceptor_finalize (
    GumScriptInterceptor * self);

G_GNUC_INTERNAL void _gum_script_interceptor_on_enter (
    GumScriptInterceptor * self, GumInvocationContext * context);
G_GNUC_INTERNAL void _gum_script_interceptor_on_leave (
    GumScriptInterceptor * self, GumInvocationContext * context);

#endif
