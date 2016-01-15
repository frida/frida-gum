/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_INTERCEPTOR_H__
#define __GUM_DUKRIPT_INTERCEPTOR_H__

#include "gumdukcore.h"

#include <gum/guminterceptor.h>

G_BEGIN_DECLS

typedef struct _GumDukInterceptor GumDukInterceptor;

typedef struct _GumDukInvocationContext GumDukInvocationContext;
typedef struct _GumDukInvocationArgs GumDukInvocationArgs;
typedef struct _GumDukInvocationReturnValue GumDukInvocationReturnValue;

struct _GumDukInterceptor
{
  GumDukCore * core;

  GumInterceptor * interceptor;

  GQueue * attach_entries;
  GHashTable * replacement_by_address;

  GumDukHeapPtr invocation_context;
  GumDukHeapPtr invocation_args;
  GumDukHeapPtr invocation_retval;

  GumDukInvocationContext * cached_invocation_context;
  gboolean cached_invocation_context_in_use;

  GumDukInvocationArgs * cached_invocation_args;
  gboolean cached_invocation_args_in_use;

  GumDukInvocationReturnValue * cached_invocation_return_value;
  gboolean cached_invocation_return_value_in_use;
};

G_GNUC_INTERNAL void _gum_duk_interceptor_init (GumDukInterceptor * self,
    GumDukCore * core, duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_interceptor_flush (GumDukInterceptor * self,
    duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_interceptor_dispose (GumDukInterceptor * self,
    duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_interceptor_finalize (GumDukInterceptor * self);

G_GNUC_INTERNAL void _gum_duk_interceptor_on_enter (
    GumDukInterceptor * self, GumInvocationContext * context);
G_GNUC_INTERNAL void _gum_duk_interceptor_on_leave (
    GumDukInterceptor * self, GumInvocationContext * context);

G_END_DECLS

#endif
