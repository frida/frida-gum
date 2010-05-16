/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include <glib-object.h>
#include <gum/gumdefs.h>

typedef struct _FunctionContext          FunctionContext;
typedef struct _FunctionThreadContext    FunctionThreadContext;

struct _FunctionThreadContext
{
  FunctionContext * function_ctx;

  guint thread_id;

  gpointer listener_data[GUM_MAX_LISTENERS_PER_FUNCTION];
  guint listener_data_count;
};

struct _FunctionContext
{
  gpointer function_address;

  gpointer trampoline;
  guint8 * overwritten_prologue;
  guint overwritten_prologue_len;

  GPtrArray * listener_entries;

  /* state */
  FunctionThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

G_BEGIN_DECLS

void _gum_function_ctx_make_monitor_trampoline (FunctionContext * ctx);
void _gum_function_ctx_make_replace_trampoline (FunctionContext * ctx,
    gpointer replacement_address, gpointer user_data);
void _gum_function_ctx_destroy_trampoline (FunctionContext * ctx);
void _gum_function_ctx_activate_trampoline (FunctionContext * ctx);
void _gum_function_ctx_deactivate_trampoline (FunctionContext * ctx);

guint _gum_interceptor_find_displacement_size (gpointer function_address,
    guint bytes_needed);

void _gum_interceptor_function_context_on_enter_thunk ();
void _gum_interceptor_function_context_on_leave_thunk ();

void _gum_interceptor_function_context_on_enter (
    FunctionContext * function_ctx, GumCpuContext * cpu_context,
    gpointer * caller_ret_addr, gpointer function_arguments);
gpointer _gum_interceptor_function_context_on_leave (
    gpointer function_return_value);

G_END_DECLS

#endif
