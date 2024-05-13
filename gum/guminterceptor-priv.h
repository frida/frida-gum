/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2024 Yannis Juglaret <yjuglaret@mozilla.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INTERCEPTOR_PRIV_H__
#define __GUM_INTERCEPTOR_PRIV_H__

#include "guminterceptor.h"

#include "gumcodeallocator.h"
#include "gumspinlock.h"
#include "gumtls.h"

typedef struct _GumInterceptorBackend GumInterceptorBackend;
typedef guint8 GumInterceptorType;
typedef struct _GumFunctionContext GumFunctionContext;
typedef union _GumFunctionContextBackendData GumFunctionContextBackendData;

enum _GumInterceptorType
{
  GUM_INTERCEPTOR_TYPE_DEFAULT = 0,
  GUM_INTERCEPTOR_TYPE_FAST    = 1
};

union _GumFunctionContextBackendData
{
  gchar storage[2 * GLIB_SIZEOF_VOID_P];
  gpointer p[2];
};

struct _GumFunctionContext
{
  gpointer function_address;

  gpointer grafted_hook;
  gpointer import_target;

  GumInterceptorType type;
  guint8 destroyed;
  guint8 activated;
  guint8 has_on_leave_listener;

  GumCodeSlice * trampoline_slice;
  GumCodeDeflector * trampoline_deflector;
  volatile gint trampoline_usage_counter;

  gpointer on_enter_trampoline;
  guint8 overwritten_prologue[32];
  guint overwritten_prologue_len;

  gpointer on_invoke_trampoline;

  gpointer on_leave_trampoline;

  volatile GPtrArray * listener_entries;

  gpointer replacement_function;
  gpointer replacement_data;

  GumFunctionContextBackendData backend_data;

  GumInterceptor * interceptor;
};

G_GNUC_INTERNAL void _gum_interceptor_init (void);
G_GNUC_INTERNAL void _gum_interceptor_deinit (void);

G_GNUC_INTERNAL gboolean _gum_function_context_begin_invocation (
    GumFunctionContext * function_ctx, GumCpuContext * cpu_context,
    gpointer * caller_ret_addr, gpointer * next_hop);
G_GNUC_INTERNAL void _gum_function_context_end_invocation (
    GumFunctionContext * function_ctx, GumCpuContext * cpu_context,
    gpointer * next_hop);

G_GNUC_INTERNAL GumInterceptorBackend * _gum_interceptor_backend_create (
    GRecMutex * mutex, GumCodeAllocator * allocator);
G_GNUC_INTERNAL void _gum_interceptor_backend_destroy (
    GumInterceptorBackend * backend);
G_GNUC_INTERNAL gboolean _gum_interceptor_backend_claim_grafted_trampoline (
    GumInterceptorBackend * self, GumFunctionContext * ctx);
G_GNUC_INTERNAL gboolean _gum_interceptor_backend_create_trampoline (
    GumInterceptorBackend * self, GumFunctionContext * ctx);
G_GNUC_INTERNAL void _gum_interceptor_backend_destroy_trampoline (
    GumInterceptorBackend * self, GumFunctionContext * ctx);
G_GNUC_INTERNAL void _gum_interceptor_backend_activate_trampoline (
    GumInterceptorBackend * self, GumFunctionContext * ctx, gpointer prologue);
G_GNUC_INTERNAL void _gum_interceptor_backend_deactivate_trampoline (
    GumInterceptorBackend * self, GumFunctionContext * ctx, gpointer prologue);

G_GNUC_INTERNAL gpointer _gum_interceptor_backend_get_function_address (
    GumFunctionContext * ctx);
G_GNUC_INTERNAL gpointer _gum_interceptor_backend_resolve_redirect (
    GumInterceptorBackend * self, gpointer address);
G_GNUC_INTERNAL gboolean _gum_interceptor_backend_can_intercept (
    GumInterceptorBackend * self, gpointer function_address);

G_GNUC_INTERNAL gpointer _gum_interceptor_peek_top_caller_return_address (void);
G_GNUC_INTERNAL gpointer _gum_interceptor_translate_top_return_address (
    gpointer return_address);

#endif
