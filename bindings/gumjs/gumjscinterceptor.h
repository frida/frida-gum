/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_INTERCEPTOR_H__
#define __GUM_JSCRIPT_INTERCEPTOR_H__

#include "gumjsccore.h"

#include <gum/guminterceptor.h>

G_BEGIN_DECLS

typedef struct _GumJscInterceptor GumJscInterceptor;

struct _GumJscInterceptor
{
  GumJscCore * core;

  GumInterceptor * interceptor;

  GQueue * attach_entries;
  GHashTable * replacement_by_address;

  JSClassRef invocation_context;
  JSClassRef invocation_args;
  JSClassRef invocation_retval;
};

G_GNUC_INTERNAL void _gum_jsc_interceptor_init (GumJscInterceptor * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_interceptor_dispose (
    GumJscInterceptor * self);
G_GNUC_INTERNAL void _gum_jsc_interceptor_finalize (
    GumJscInterceptor * self);

G_GNUC_INTERNAL void _gum_jsc_interceptor_on_enter (
    GumJscInterceptor * self, GumInvocationContext * context);
G_GNUC_INTERNAL void _gum_jsc_interceptor_on_leave (
    GumJscInterceptor * self, GumInvocationContext * context);

G_END_DECLS

#endif
