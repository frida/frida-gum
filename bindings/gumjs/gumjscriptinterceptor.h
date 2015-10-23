/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_INTERCEPTOR_H__
#define __GUM_JSCRIPT_INTERCEPTOR_H__

#include "gumjscriptcore.h"

#include <gum/guminterceptor.h>

G_BEGIN_DECLS

typedef struct _GumScriptInterceptor GumScriptInterceptor;

struct _GumScriptInterceptor
{
  GumScriptCore * core;

  GumInterceptor * interceptor;

  GQueue * attach_entries;
  GHashTable * replacement_by_address;

  JSClassRef invocation_args;
};

G_GNUC_INTERNAL void _gum_script_interceptor_init (GumScriptInterceptor * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_interceptor_dispose (
    GumScriptInterceptor * self);
G_GNUC_INTERNAL void _gum_script_interceptor_finalize (
    GumScriptInterceptor * self);

G_GNUC_INTERNAL void _gum_script_interceptor_on_enter (
    GumScriptInterceptor * self, GumInvocationContext * context);
G_GNUC_INTERNAL void _gum_script_interceptor_on_leave (
    GumScriptInterceptor * self, GumInvocationContext * context);

G_END_DECLS

#endif
