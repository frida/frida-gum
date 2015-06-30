/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INTERCEPTOR_PRIV_H__
#define __GUM_INTERCEPTOR_PRIV_H__

#include "guminterceptor.h"

#include "gumarray.h"
#include "gumcodeallocator.h"
#include "gumspinlock.h"
#include "gumtls.h"

typedef struct _FunctionContext          FunctionContext;

struct _FunctionContext
{
  GumInterceptor * interceptor;

  gpointer function_address;

  GumCodeAllocator * allocator;
  GumCodeSlice * trampoline_slice;
  volatile gint * trampoline_usage_counter;

  gpointer on_enter_trampoline;
  guint8 overwritten_prologue[32];
  guint overwritten_prologue_len;

  gpointer on_leave_trampoline;

  GumArray * listener_entries;

  gpointer replacement_function_data;
};

extern GumTlsKey _gum_interceptor_guard_key;

G_GNUC_INTERNAL void _gum_interceptor_init (void);
G_GNUC_INTERNAL void _gum_interceptor_deinit (void);

gboolean _gum_function_context_on_enter (FunctionContext * function_ctx,
    GumCpuContext * cpu_context, gpointer * caller_ret_addr);
void _gum_function_context_on_leave (FunctionContext * function_ctx,
    GumCpuContext * cpu_context, gpointer * caller_ret_addr);

gboolean _gum_function_context_try_begin_invocation (
    FunctionContext * function_ctx, gpointer caller_ret_addr,
    const GumCpuContext * cpu_context);
gpointer _gum_function_context_end_invocation (void);

#ifdef HAVE_QNX
gpointer _gum_interceptor_thread_get_side_stack (gpointer original_stack);
gpointer _gum_interceptor_thread_get_orig_stack (gpointer current_stack);
#endif

void _gum_function_context_init (void);
void _gum_function_context_deinit (void);
void _gum_function_context_make_monitor_trampoline (FunctionContext * ctx);
void _gum_function_context_make_replace_trampoline (FunctionContext * ctx,
    gpointer replacement_function);
void _gum_function_context_destroy_trampoline (FunctionContext * ctx);
void _gum_function_context_activate_trampoline (FunctionContext * ctx);
void _gum_function_context_deactivate_trampoline (FunctionContext * ctx);

gpointer _gum_interceptor_resolve_redirect (gpointer address);
gboolean _gum_interceptor_can_intercept (gpointer function_address);

gpointer _gum_interceptor_invocation_get_nth_argument (
    GumInvocationContext * context, guint n);
void _gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context, guint n, gpointer value);
gpointer _gum_interceptor_invocation_get_return_value (
    GumInvocationContext * context);
void _gum_interceptor_invocation_replace_return_value (
    GumInvocationContext * context, gpointer value);

#endif

