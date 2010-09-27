/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUM_INTERCEPTOR_PRIV_H__
#define __GUM_INTERCEPTOR_PRIV_H__

#include "guminterceptor.h"

#include "gumcodeallocator.h"
#include "gumspinlock.h"

typedef struct _FunctionContext          FunctionContext;
typedef struct _FunctionThreadContext    FunctionThreadContext;

struct _FunctionThreadContext
{
  FunctionContext * function_ctx;

  guint thread_id;

  gpointer listener_data[GUM_MAX_LISTENERS_PER_FUNCTION];
  guint listener_data_count;
  GumInvocationBackend invocation_backend;
};

struct _FunctionContext
{
  gpointer function_address;

  GumCodeAllocator * allocator;
  GumCodeSlice * trampoline_slice;
  volatile gint * trampoline_usage_counter;

  gpointer on_enter_trampoline;
  guint8 overwritten_prologue[32];
  guint overwritten_prologue_len;

  gpointer on_leave_trampoline;

  GumSpinlock listener_lock;
  GPtrArray * listener_entries;

  /* state */
  FunctionThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

G_GNUC_INTERNAL void _gum_interceptor_deinit (void);

gboolean _gum_function_context_on_enter (FunctionContext * function_ctx,
    GumCpuContext * cpu_context, gpointer * caller_ret_addr);
gpointer _gum_function_context_on_leave (FunctionContext * function_ctx,
    GumCpuContext * cpu_context);

gboolean _gum_function_context_try_begin_invocation (GCallback function,
    gpointer caller_ret_addr, const GumCpuContext * cpu_context,
    gpointer user_data);
gpointer _gum_function_context_end_invocation (void);

void _gum_function_context_make_monitor_trampoline (FunctionContext * ctx);
void _gum_function_context_make_replace_trampoline (FunctionContext * ctx,
    gpointer replacement_address, gpointer user_data);
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

#endif

