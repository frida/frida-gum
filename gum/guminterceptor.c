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

#include "guminterceptor.h"
#include "guminterceptor-priv.h"

#include "gumarray.h"
#include "gumcodereader.h"
#include "gumhash.h"
#include "gummemory.h"
#include "gumrelocator.h"

#include <string.h>
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
typedef DWORD GumTlsKey;
#define GUM_TLS_KEY_GET_VALUE(k)    TlsGetValue (k)
#define GUM_TLS_KEY_SET_VALUE(k, v) TlsSetValue (k, v)
#else
#include <pthread.h>
typedef pthread_key_t GumTlsKey;
#define GUM_TLS_KEY_GET_VALUE(k)    pthread_getspecific (k)
#define GUM_TLS_KEY_SET_VALUE(k, v) pthread_setspecific (k, v)
#endif

G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT);

#define GUM_INTERCEPTOR_LOCK()   (g_mutex_lock (priv->mutex))
#define GUM_INTERCEPTOR_UNLOCK() (g_mutex_unlock (priv->mutex))

typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _ListenerEntry            ListenerEntry;
typedef struct _ThreadContextStackEntry  ThreadContextStackEntry;

struct _GumInterceptorPrivate
{
  GMutex * mutex;

  GumHashTable * monitored_function_by_address;
  GumHashTable * replaced_function_by_address;
};

struct _InterceptorThreadContext
{
  guint ignore_level;
  GumArray * stack;
};

struct _ListenerEntry
{
  GumInvocationListenerIface * listener_interface;
  GumInvocationListener * listener_instance;
  gpointer function_instance_data;
};

struct _ThreadContextStackEntry
{
  FunctionThreadContext * thread_ctx;
  gpointer caller_ret_addr;
};

#define GUM_INTERCEPTOR_GET_PRIVATE(o) ((o)->priv)

static void gum_interceptor_finalize (GObject * object);

static void the_interceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static FunctionContext * intercept_function_at (GumInterceptor * self,
    gpointer function_address);
static void replace_function_at (GumInterceptor * self,
    gpointer function_address, gpointer replacement_address,
    gpointer user_data);
static void revert_function_at (GumInterceptor * self,
    gpointer function_address);
static void detach_if_matching_listener (gpointer key, gpointer value,
    gpointer user_data);
static FunctionContext * function_context_new (gpointer function_address);
static void function_context_destroy (FunctionContext * function_ctx);
static void function_context_add_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener, gpointer function_instance_data);
static void function_context_remove_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static gboolean function_context_has_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static ListenerEntry * function_context_find_listener_entry (
    FunctionContext * function_ctx, GumInvocationListener * listener);

static void fill_parent_context_for_listener (
    FunctionThreadContext * parent_thread_ctx,
    GumInvocationListener * listener, GumInvocationContext * parent_context);
FunctionThreadContext * get_thread_context (FunctionContext * function_ctx);
static InterceptorThreadContext * get_interceptor_thread_context (void);
static gpointer thread_context_stack_peek_top_and_push (
    FunctionThreadContext * thread_ctx, gpointer caller_ret_addr);
static gpointer thread_context_stack_pop_and_peek_top (
    FunctionThreadContext ** thread_ctx, gpointer * caller_ret_addr);

static void make_function_prologue_read_write_execute (
    gpointer prologue_address);
static gpointer maybe_follow_redirect_at (GumInterceptor * self,
    gpointer address);

static gboolean is_patched_function (GumInterceptor * self,
    gpointer function_address);
static gboolean can_intercept_function (gpointer function_address);

static guint get_current_thread_id (void);

static GStaticMutex _gum_interceptor_mutex = G_STATIC_MUTEX_INIT;
static GumInterceptor * _the_interceptor = NULL;

static GumTlsKey _gum_interceptor_tls_key;

#ifndef G_OS_WIN32
static GumTlsKey _gum_interceptor_tid_key;
static volatile gint _gum_interceptor_tid_counter = 0;
#endif

static void
gum_interceptor_class_init (GumInterceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

#ifdef G_OS_WIN32
  _gum_interceptor_tls_key = TlsAlloc ();
#else
  pthread_key_create (&_gum_interceptor_tls_key, NULL);
  pthread_key_create (&_gum_interceptor_tid_key, NULL);
#endif

  g_type_class_add_private (klass, sizeof (GumInterceptorPrivate));

  object_class->finalize = gum_interceptor_finalize;
}

static void
gum_interceptor_init (GumInterceptor * self)
{
  GumInterceptorPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_INTERCEPTOR,
      GumInterceptorPrivate);

  priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  priv->mutex = g_mutex_new ();

  priv->monitored_function_by_address = gum_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);
  priv->replaced_function_by_address = gum_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);
}

static void
gum_interceptor_finalize (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  g_mutex_free (priv->mutex);

  gum_hash_table_unref (priv->monitored_function_by_address);
  gum_hash_table_unref (priv->replaced_function_by_address);

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_static_mutex_lock (&_gum_interceptor_mutex);

  if (_the_interceptor != NULL)
  {
    interceptor = g_object_ref (_the_interceptor);
  }
  else
  {
    interceptor = _the_interceptor = g_object_new (GUM_TYPE_INTERCEPTOR, NULL);
    g_object_weak_ref (G_OBJECT (_the_interceptor),
        the_interceptor_weak_notify, NULL);
  }

  g_static_mutex_unlock (&_gum_interceptor_mutex);

  return interceptor;
}

static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  g_static_mutex_lock (&_gum_interceptor_mutex);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_static_mutex_unlock (&_gum_interceptor_mutex);
}

GumAttachReturn
gum_interceptor_attach_listener (GumInterceptor * self,
                                 gpointer function_address,
                                 GumInvocationListener * listener,
                                 gpointer function_instance_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  GumAttachReturn result = GUM_ATTACH_OK;
  gpointer next_hop;
  FunctionContext * function_ctx;

  gum_interceptor_ignore_caller (self);
  GUM_INTERCEPTOR_LOCK ();

  make_function_prologue_read_write_execute (function_address);

  while (TRUE)
  {
    next_hop = maybe_follow_redirect_at (self, function_address);
    if (next_hop != function_address)
      function_address = next_hop;
    else
      break;
  }

  function_ctx = gum_hash_table_lookup (priv->monitored_function_by_address,
      function_address);
  if (function_ctx == NULL)
  {
    make_function_prologue_read_write_execute (function_address);

    if (!can_intercept_function (function_address))
    {
      result = GUM_ATTACH_WRONG_SIGNATURE;
      goto beach;
    }

    function_ctx = intercept_function_at (self, function_address);
    gum_hash_table_insert (priv->monitored_function_by_address,
        function_address, function_ctx);
  }
  else
  {
    if (function_context_has_listener (function_ctx, listener))
    {
      result = GUM_ATTACH_ALREADY_ATTACHED;
      goto beach;
    }
  }

  function_context_add_listener (function_ctx, listener,
      function_instance_data);

beach:
  GUM_INTERCEPTOR_UNLOCK ();
  gum_interceptor_unignore_caller (self);

  return result;
}

typedef struct {
  GumInterceptor * self;
  GumInvocationListener * listener;
  GList * pending_removals;
} DetachContext;

void
gum_interceptor_detach_listener (GumInterceptor * self,
                                 GumInvocationListener * listener)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  DetachContext ctx;
  GList * walk;

  gum_interceptor_ignore_caller (self);
  GUM_INTERCEPTOR_LOCK ();

  ctx.self = self;
  ctx.listener = listener;
  ctx.pending_removals = NULL;

  gum_hash_table_foreach (priv->monitored_function_by_address,
      detach_if_matching_listener, &ctx);

  while ((walk = ctx.pending_removals) != NULL)
  {
    gpointer function_address = walk->data;
    gum_hash_table_remove (priv->monitored_function_by_address,
        function_address);
    ctx.pending_removals =
        g_list_remove_all (ctx.pending_removals, function_address);
  }

  GUM_INTERCEPTOR_UNLOCK ();
  gum_interceptor_unignore_caller (self);
}

void
gum_interceptor_replace_function (GumInterceptor * self,
                                  gpointer function_address,
                                  gpointer replacement_address,
                                  gpointer user_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  GUM_INTERCEPTOR_LOCK ();

  make_function_prologue_read_write_execute (function_address);
  function_address = maybe_follow_redirect_at (self, function_address);
  make_function_prologue_read_write_execute (function_address);

  replace_function_at (self, function_address, replacement_address, user_data);

  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_revert_function (GumInterceptor * self,
                                 gpointer function_address)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  GUM_INTERCEPTOR_LOCK ();

  make_function_prologue_read_write_execute (function_address);
  function_address = maybe_follow_redirect_at (self, function_address);
  make_function_prologue_read_write_execute (function_address);

  revert_function_at (self, function_address);

  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_ignore_caller (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level++;
}

void
gum_interceptor_unignore_caller (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level--;
}

static FunctionContext *
intercept_function_at (GumInterceptor * self,
                       gpointer function_address)
{
  FunctionContext * ctx;

  ctx = function_context_new (function_address);

  ctx->listener_entries = g_ptr_array_sized_new (2);

  _gum_function_ctx_make_monitor_trampoline (ctx);
  _gum_function_ctx_activate_trampoline (ctx);

#ifdef G_OS_WIN32
  FlushInstructionCache (GetCurrentProcess (), NULL, 0);
#endif

  return ctx;
}

static void
replace_function_at (GumInterceptor * self,
                     gpointer function_address,
                     gpointer replacement_address,
                     gpointer user_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  FunctionContext * ctx;

  ctx = function_context_new (function_address);

  _gum_function_ctx_make_replace_trampoline (ctx, replacement_address,
      user_data);
  _gum_function_ctx_activate_trampoline (ctx);

  gum_hash_table_insert (priv->replaced_function_by_address, function_address,
      ctx);

#ifdef G_OS_WIN32
  FlushInstructionCache (GetCurrentProcess (), NULL, 0);
#endif
}

static void
revert_function_at (GumInterceptor * self,
                    gpointer function_address)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  FunctionContext * ctx;

  ctx = gum_hash_table_lookup (priv->replaced_function_by_address,
      function_address);
  g_assert (ctx != NULL);

  gum_hash_table_remove (priv->replaced_function_by_address, function_address);

  function_context_destroy (ctx);

#ifdef G_OS_WIN32
  FlushInstructionCache (GetCurrentProcess (), NULL, 0);
#endif
}

static void
detach_if_matching_listener (gpointer key,
                             gpointer value,
                             gpointer user_data)
{
  gpointer function_address = key;
  FunctionContext * function_ctx = value;
  DetachContext * detach_ctx = user_data;

  if (function_context_has_listener (function_ctx, detach_ctx->listener))
  {
    function_context_remove_listener (function_ctx, detach_ctx->listener);

    if (function_ctx->listener_entries->len == 0)
    {
      function_context_destroy (function_ctx);

      detach_ctx->pending_removals =
          g_list_prepend (detach_ctx->pending_removals, function_address);
    }
  }
}

static FunctionContext *
function_context_new (gpointer function_address)
{
  FunctionContext * ctx;

  ctx = gum_malloc0 (sizeof (FunctionContext));
  ctx->function_address = function_address;

  return ctx;
}

static void
function_context_destroy (FunctionContext * function_ctx)
{
  if (function_ctx->trampoline != NULL)
  {
    _gum_function_ctx_deactivate_trampoline (function_ctx);
    _gum_function_ctx_destroy_trampoline (function_ctx);
  }

  gum_free (function_ctx);
}

static void
function_context_add_listener (FunctionContext * function_ctx,
                               GumInvocationListener * listener,
                               gpointer function_instance_data)
{
  ListenerEntry * entry;

  entry = g_new (ListenerEntry, 1);
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_INTERFACE (listener);
  entry->listener_instance = listener;
  entry->function_instance_data = function_instance_data;
  g_ptr_array_add (function_ctx->listener_entries, entry);
}

static void
function_context_remove_listener (FunctionContext * function_ctx,
                                  GumInvocationListener * listener)
{
  ListenerEntry * entry;

  entry = function_context_find_listener_entry (function_ctx, listener);
  g_assert (entry != NULL);
  g_ptr_array_remove (function_ctx->listener_entries, entry);

  g_free (entry);
}

static gboolean
function_context_has_listener (FunctionContext * function_ctx,
                               GumInvocationListener * listener)
{
  return function_context_find_listener_entry (function_ctx, listener) != NULL;
}

static ListenerEntry *
function_context_find_listener_entry (FunctionContext * function_ctx,
                                      GumInvocationListener * listener)
{
  guint i;

  for (i = 0; i < function_ctx->listener_entries->len; i++)
  {
    ListenerEntry * entry = (ListenerEntry *)
        g_ptr_array_index (function_ctx->listener_entries, i);

    if (entry->listener_instance == listener)
      return entry;
  }

  return NULL;
}

static gpointer
gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                             guint n)
{
  gpointer * first_argument_on_stack;

#if GLIB_SIZEOF_VOID_P == 4
  first_argument_on_stack = (gpointer *) context->cpu_context->esp;
#else
  first_argument_on_stack = (gpointer *) context->cpu_context->rsp;
#endif

  return first_argument_on_stack[n];
}

static gpointer
gum_interceptor_invocation_get_return_value (GumInvocationContext * context)
{
#if GLIB_SIZEOF_VOID_P == 4
  return (gpointer) context->cpu_context->eax;
#else
  return (gpointer) context->cpu_context->rax;
#endif
}

static const GumInvocationBackend gum_interceptor_invocation_backend_template =
{
  gum_interceptor_invocation_get_nth_argument,
  gum_interceptor_invocation_get_return_value,

  NULL
};

void
_gum_interceptor_function_context_on_enter (FunctionContext * function_ctx,
                                            GumCpuContext * cpu_context,
                                            gpointer * caller_ret_addr,
                                            gpointer function_arguments)
{
  InterceptorThreadContext * interceptor_ctx;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

#if GLIB_SIZEOF_VOID_P == 4
  cpu_context->esp = (guint32) function_arguments;
  cpu_context->eip = (guint32) *caller_ret_addr;
#else
  cpu_context->rsp = (guint64) function_arguments;
  cpu_context->rip = (guint64) *caller_ret_addr;
#endif

  interceptor_ctx = get_interceptor_thread_context ();
  if (interceptor_ctx->ignore_level == 0)
  {
    FunctionThreadContext * thread_ctx, * parent_thread_ctx;
    GPtrArray * listener_entries;
    guint i;

    thread_ctx = get_thread_context (function_ctx);

    parent_thread_ctx = (FunctionThreadContext *)
        thread_context_stack_peek_top_and_push (thread_ctx, *caller_ret_addr);
#ifdef _M_IX86 /* FIXME */
    *caller_ret_addr = _gum_interceptor_function_context_on_leave_thunk;
#endif

    listener_entries = thread_ctx->function_ctx->listener_entries;
    for (i = 0; i < listener_entries->len; i++)
    {
      ListenerEntry * entry = (ListenerEntry *)
          g_ptr_array_index (listener_entries, i);
      GumInvocationBackend backend;
      GumInvocationContext context, parent_context;

      backend = gum_interceptor_invocation_backend_template;
      backend.user_data = entry;

      context.instance_data = entry->function_instance_data;

      if (i < thread_ctx->listener_data_count)
      {
        context.thread_data = thread_ctx->listener_data[i];
      }
      else
      {
        context.thread_data = entry->listener_interface->provide_thread_data (
            entry->listener_instance, entry->function_instance_data,
            get_current_thread_id ());

        thread_ctx->listener_data_count++;
        g_assert (thread_ctx->listener_data_count <=
            G_N_ELEMENTS (thread_ctx->listener_data));

        thread_ctx->listener_data[i] = context.thread_data;
      }

      fill_parent_context_for_listener (parent_thread_ctx,
          entry->listener_instance, &parent_context);
      context.parent = &parent_context;

      context.cpu_context = cpu_context;
      context.backend = &backend;

      entry->listener_interface->on_enter (entry->listener_instance, &context);
    }
  }

#ifdef G_OS_WIN32
  SetLastError (previous_last_error);
#endif
}

gpointer
_gum_interceptor_function_context_on_leave (gpointer function_return_value)
{
  FunctionThreadContext * thread_ctx, * parent_thread_ctx;
  gpointer caller_ret_addr;
  GPtrArray * listener_entries;
  guint i;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

  parent_thread_ctx = (FunctionThreadContext *)
      thread_context_stack_pop_and_peek_top (&thread_ctx, &caller_ret_addr);

  listener_entries = thread_ctx->function_ctx->listener_entries;
  for (i = 0; i < listener_entries->len; i++)
  {
    ListenerEntry * entry = (ListenerEntry *)
        g_ptr_array_index (listener_entries, i);
    GumInvocationBackend backend;
    GumInvocationContext context, parent_context;
    GumCpuContext cpu_context = { 0, };

    /* FIXME */
#if GLIB_SIZEOF_VOID_P == 4
    cpu_context.eax = (guint32) function_return_value;
#else
    cpu_context.rax = (guint64) function_return_value;
#endif

    backend = gum_interceptor_invocation_backend_template;
    backend.user_data = entry;

    context.instance_data = entry->function_instance_data;
    context.thread_data = thread_ctx->listener_data[i];

    fill_parent_context_for_listener (parent_thread_ctx,
        entry->listener_instance, &parent_context);
    context.parent = &parent_context;

    context.cpu_context = &cpu_context;
    context.backend = &backend;

    entry->listener_interface->on_leave (entry->listener_instance, &context);
  }

#ifdef G_OS_WIN32
  SetLastError (previous_last_error);
#endif

  return caller_ret_addr;
}

static void
fill_parent_context_for_listener (FunctionThreadContext * parent_thread_ctx,
                                  GumInvocationListener * listener,
                                  GumInvocationContext * parent_context)
{
  parent_context->parent = NULL;
  parent_context->cpu_context = NULL;
  parent_context->backend = NULL;

  if (parent_thread_ctx != NULL)
  {
    guint i;
    GPtrArray * entries;

    entries = parent_thread_ctx->function_ctx->listener_entries;
    for (i = 0; i < entries->len; i++)
    {
      ListenerEntry * entry = (ListenerEntry *) g_ptr_array_index (entries, i);

      if (entry->listener_instance == listener)
      {
        parent_context->instance_data = entry->function_instance_data;
        parent_context->thread_data = parent_thread_ctx->listener_data[i];
        return;
      }
    }
  }

  parent_context->instance_data = NULL;
  parent_context->thread_data = NULL;
}

FunctionThreadContext *
get_thread_context (FunctionContext * function_ctx)
{
  guint32 thread_id;
  guint thread_count = function_ctx->thread_context_count;
  guint i;
  FunctionThreadContext * thread_ctx;

  thread_id = get_current_thread_id ();

  for (i = 0; i < thread_count; i++)
  {
    thread_ctx = &function_ctx->thread_contexts[i];
    if (thread_ctx->thread_id == thread_id)
      return thread_ctx;
  }

  i = g_atomic_int_exchange_and_add (&function_ctx->thread_context_count, 1);
  g_assert (i < G_N_ELEMENTS (function_ctx->thread_contexts));
  thread_ctx = &function_ctx->thread_contexts[i];
  thread_ctx->function_ctx = function_ctx;

  thread_ctx->thread_id = thread_id;

  return thread_ctx;
}

static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = GUM_TLS_KEY_GET_VALUE (_gum_interceptor_tls_key);
  if (context == NULL)
  {
    context = gum_malloc (sizeof (InterceptorThreadContext));
    context->ignore_level = 0;
    context->stack = gum_array_sized_new (FALSE, FALSE,
        sizeof (ThreadContextStackEntry), GUM_MAX_CALL_DEPTH);

    GUM_TLS_KEY_SET_VALUE (_gum_interceptor_tls_key, context);
  }

  return context;
}

static gpointer
thread_context_stack_peek_top_and_push (FunctionThreadContext * thread_ctx,
                                        gpointer caller_ret_addr)
{
  gpointer prev_top_thread_ctx = NULL;
  InterceptorThreadContext * context;
  GumArray * stack;
  ThreadContextStackEntry entry;

  context = get_interceptor_thread_context ();
  stack = context->stack;

  entry.thread_ctx = thread_ctx;
  entry.caller_ret_addr = caller_ret_addr;

  if (stack->len > 0)
  {
    prev_top_thread_ctx = g_array_index (stack, ThreadContextStackEntry,
        stack->len - 1).thread_ctx;
  }

  gum_array_append_val (stack, entry);

  return prev_top_thread_ctx;
}

static gpointer
thread_context_stack_pop_and_peek_top (FunctionThreadContext ** thread_ctx,
                                       gpointer * caller_ret_addr)
{
  InterceptorThreadContext * context;
  GumArray * stack;
  ThreadContextStackEntry * entry;

  context = get_interceptor_thread_context ();
  stack = context->stack;

  entry = &g_array_index (stack, ThreadContextStackEntry, stack->len - 1);
  *thread_ctx = entry->thread_ctx;
  *caller_ret_addr = entry->caller_ret_addr;
  gum_array_set_size (stack, stack->len - 1);

  if (stack->len > 0)
  {
    return gum_array_index (stack, ThreadContextStackEntry,
        stack->len - 1).thread_ctx;
  }
  else
  {
    return NULL;
  }
}

static void
make_function_prologue_read_write_execute (gpointer prologue_address)
{
  gum_mprotect (prologue_address, 16, GUM_PAGE_READ | GUM_PAGE_WRITE
      | GUM_PAGE_EXECUTE);
}

static gpointer
maybe_follow_redirect_at (GumInterceptor * self,
                          gpointer address)
{
  if (!is_patched_function (self, address))
  {
    gpointer target;

    target = gum_code_reader_try_get_relative_jump_target (address);
    if (target == NULL)
      target = gum_code_reader_try_get_indirect_jump_target (address);

    if (target != NULL)
      return target;
  }

  return address;
}

static gboolean
is_patched_function (GumInterceptor * self,
                     gpointer function_address)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  if (gum_hash_table_lookup (priv->monitored_function_by_address,
      function_address) != NULL)
  {
    return TRUE;
  }
  else if (gum_hash_table_lookup (priv->replaced_function_by_address,
      function_address) != NULL)
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

static gboolean
can_intercept_function (gpointer function_address)
{
#if GLIB_SIZEOF_VOID_P == 8
  return (_gum_interceptor_find_displacement_size (function_address,
      GUM_REDIRECT_CODE_SIZE) != 0);
#else
  return gum_relocator_can_relocate (function_address, GUM_REDIRECT_CODE_SIZE);
#endif
}

static guint
get_current_thread_id (void)
{
#ifdef G_OS_WIN32
  return GetCurrentThreadId ();
#else
  guint id;

  id = GPOINTER_TO_UINT (GUM_TLS_KEY_GET_VALUE (_gum_interceptor_tid_key));
  if (id == 0)
  {
    id = g_atomic_int_exchange_and_add (&_gum_interceptor_tid_counter, 1) + 1;
    GUM_TLS_KEY_SET_VALUE (_gum_interceptor_tid_key, GUINT_TO_POINTER (id));
  }

  return id;
#endif
}
