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
#include "gumhash.h"
#include "gummemory.h"
#include "gumtls.h"

#include <string.h>

#define GUM_INTERCEPTOR_CODE_SLICE_SIZE     400

G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT);

#define GUM_INTERCEPTOR_LOCK()   (g_mutex_lock (priv->mutex))
#define GUM_INTERCEPTOR_UNLOCK() (g_mutex_unlock (priv->mutex))

typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _ListenerEntry            ListenerEntry;
typedef GumArray                         ThreadContextStack;
typedef struct _ThreadContextStackEntry  ThreadContextStackEntry;
typedef struct _ListenerInvocationData   ListenerInvocationData;

struct _GumInterceptorPrivate
{
  GMutex * mutex;

  GumHashTable * monitored_function_by_address;
  GumHashTable * replaced_function_by_address;

  GumCodeAllocator allocator;
};

struct _InterceptorThreadContext
{
  guint ignore_level;
  ThreadContextStack * stack;
};

struct _ListenerEntry
{
  GumInvocationListenerIface * listener_interface;
  GumInvocationListener * listener_instance;
  gpointer function_instance_data;
};

struct _ThreadContextStackEntry
{
  gpointer caller_ret_addr;
  GumInvocationContext invocation_context;
  GumCpuContext cpu_context;

  FunctionThreadContext * thread_ctx;
};

struct _ListenerInvocationData
{
  ThreadContextStack * stack;
  GumInvocationListener * listener;
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
static FunctionContext * function_context_new (gpointer function_address,
    GumCodeAllocator * allocator);
static void function_context_destroy (FunctionContext * function_ctx);
static void function_context_add_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener, gpointer function_instance_data);
static void function_context_remove_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static gboolean function_context_has_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static ListenerEntry * function_context_find_listener_entry (
    FunctionContext * function_ctx, GumInvocationListener * listener);

static GumInvocationContext * find_and_fill_parent_context_for_listener (
    ThreadContextStack * stack, GumInvocationListener * listener);
FunctionThreadContext * get_function_thread_context (
    FunctionContext * function_ctx);
static InterceptorThreadContext * get_interceptor_thread_context (void);
static InterceptorThreadContext * interceptor_thread_context_new (void);
static void interceptor_thread_context_destroy (
    InterceptorThreadContext * context);
static ThreadContextStackEntry * thread_context_stack_push (
    ThreadContextStack * stack, GCallback function, gpointer caller_ret_addr,
    const GumCpuContext * cpu_context);
static gpointer thread_context_stack_pop (ThreadContextStack * stack);
static ThreadContextStackEntry * thread_context_stack_peek_top (
    ThreadContextStack * stack);
static ThreadContextStackEntry * thread_context_stack_peek_directly_below_top (
    ThreadContextStack * stack);

static void make_function_prologue_at_least_read_write (
    gpointer prologue_address);
static void make_function_prologue_read_execute (gpointer prologue_address);
static gpointer maybe_follow_redirect_at (GumInterceptor * self,
    gpointer address);

static gboolean is_patched_function (GumInterceptor * self,
    gpointer function_address);

static guint get_current_thread_id (void);

static void gum_function_context_wait_for_idle_trampoline (
    FunctionContext * ctx);

static GStaticMutex _gum_interceptor_mutex = G_STATIC_MUTEX_INIT;
static GumInterceptor * _the_interceptor = NULL;

static gboolean _gum_interceptor_initialized = FALSE;
static GumTlsKey _gum_interceptor_tls_key;

static GumSpinlock _gum_interceptor_thread_context_lock;
static GumArray * _gum_interceptor_thread_contexts;

#ifndef G_OS_WIN32
static GumTlsKey _gum_interceptor_tid_key;
static volatile gint _gum_interceptor_tid_counter = 0;
#endif

static void
gum_interceptor_class_init (GumInterceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  GUM_TLS_KEY_INIT (&_gum_interceptor_tls_key);
#ifndef G_OS_WIN32
  GUM_TLS_KEY_INIT (&_gum_interceptor_tid_key);
#endif

  gum_spinlock_init (&_gum_interceptor_thread_context_lock);
  _gum_interceptor_thread_contexts = gum_array_new (FALSE, FALSE,
      sizeof (InterceptorThreadContext *));

  _gum_interceptor_initialized = TRUE;

  g_type_class_add_private (klass, sizeof (GumInterceptorPrivate));

  object_class->finalize = gum_interceptor_finalize;
}

void
_gum_interceptor_deinit (void)
{
  if (_gum_interceptor_initialized)
  {
    guint i;

    for (i = 0; i != _gum_interceptor_thread_contexts->len; i++)
    {
      InterceptorThreadContext * thread_ctx;

      thread_ctx = gum_array_index (_gum_interceptor_thread_contexts,
          InterceptorThreadContext *, i);
      interceptor_thread_context_destroy (thread_ctx);
    }
    gum_array_free (_gum_interceptor_thread_contexts, TRUE);
    _gum_interceptor_thread_contexts = NULL;
    gum_spinlock_free (&_gum_interceptor_thread_context_lock);

    GUM_TLS_KEY_FREE (_gum_interceptor_tls_key);
#ifndef G_OS_WIN32
    GUM_TLS_KEY_FREE (_gum_interceptor_tid_key);
#endif

    _gum_interceptor_initialized = FALSE;
  }
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

  gum_code_allocator_init (&priv->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE);
}

static void
gum_interceptor_finalize (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  g_mutex_free (priv->mutex);

  gum_hash_table_unref (priv->monitored_function_by_address);
  gum_hash_table_unref (priv->replaced_function_by_address);

  gum_code_allocator_free (&priv->allocator);

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_static_mutex_lock (&_gum_interceptor_mutex);

  if (_the_interceptor != NULL)
  {
    interceptor = GUM_INTERCEPTOR_CAST (g_object_ref (_the_interceptor));
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

  while (TRUE)
  {
    next_hop = maybe_follow_redirect_at (self, function_address);
    if (next_hop != function_address)
      function_address = next_hop;
    else
      break;
  }

  function_ctx = (FunctionContext *) gum_hash_table_lookup (
      priv->monitored_function_by_address,
      function_address);
  if (function_ctx == NULL)
  {
    if (!_gum_interceptor_can_intercept (function_address))
    {
      result = GUM_ATTACH_WRONG_SIGNATURE;
      goto beach;
    }

    make_function_prologue_at_least_read_write (function_address);
    function_ctx = intercept_function_at (self, function_address);
    make_function_prologue_read_execute (function_address);

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

  function_address = maybe_follow_redirect_at (self, function_address);

  make_function_prologue_at_least_read_write (function_address);
  replace_function_at (self, function_address, replacement_address, user_data);
  make_function_prologue_read_execute (function_address);

  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_revert_function (GumInterceptor * self,
                                 gpointer function_address)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  GUM_INTERCEPTOR_LOCK ();

  function_address = maybe_follow_redirect_at (self, function_address);

  make_function_prologue_at_least_read_write (function_address);
  revert_function_at (self, function_address);
  make_function_prologue_read_execute (function_address);

  GUM_INTERCEPTOR_UNLOCK ();
}

GumInvocationContext *
gum_interceptor_get_current_invocation (void)
{
  InterceptorThreadContext * interceptor_ctx;
  ThreadContextStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  entry = thread_context_stack_peek_top (interceptor_ctx->stack);
  if (entry == NULL)
    return NULL;

  return &entry->invocation_context;
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

  ctx = function_context_new (function_address, &self->priv->allocator);

  ctx->listener_entries = g_ptr_array_sized_new (2);

  _gum_function_context_make_monitor_trampoline (ctx);
  _gum_function_context_activate_trampoline (ctx);

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

  ctx = function_context_new (function_address, &priv->allocator);

  _gum_function_context_make_replace_trampoline (ctx, replacement_address,
      user_data);
  _gum_function_context_activate_trampoline (ctx);

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

  ctx = (FunctionContext *) gum_hash_table_lookup (
      priv->replaced_function_by_address, function_address);
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
  FunctionContext * function_ctx = (FunctionContext *) value;
  DetachContext * detach_ctx = (DetachContext *) user_data;

  if (function_context_has_listener (function_ctx, detach_ctx->listener))
  {
    function_context_remove_listener (function_ctx, detach_ctx->listener);

    if (function_ctx->listener_entries->len == 0)
    {
      make_function_prologue_at_least_read_write (function_address);
      function_context_destroy (function_ctx);
      make_function_prologue_read_execute (function_address);

      detach_ctx->pending_removals =
          g_list_prepend (detach_ctx->pending_removals, function_address);
    }
  }
}

static FunctionContext *
function_context_new (gpointer function_address,
                      GumCodeAllocator * allocator)
{
  FunctionContext * ctx;

  ctx = gum_new0 (FunctionContext, 1);
  ctx->function_address = function_address;

  ctx->allocator = allocator;

  gum_spinlock_init (&ctx->listener_lock);

  return ctx;
}

static void
function_context_destroy (FunctionContext * function_ctx)
{
  if (function_ctx->trampoline_slice != NULL)
  {
    _gum_function_context_deactivate_trampoline (function_ctx);
    gum_function_context_wait_for_idle_trampoline (function_ctx);
    _gum_function_context_destroy_trampoline (function_ctx);
  }

  if (function_ctx->listener_entries != NULL)
    g_ptr_array_free (function_ctx->listener_entries, TRUE);
  gum_spinlock_free (&function_ctx->listener_lock);

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

  gum_spinlock_acquire (&function_ctx->listener_lock);
  g_ptr_array_add (function_ctx->listener_entries, entry);
  gum_spinlock_release (&function_ctx->listener_lock);
}

static void
function_context_remove_listener (FunctionContext * function_ctx,
                                  GumInvocationListener * listener)
{
  ListenerEntry * entry;

  entry = function_context_find_listener_entry (function_ctx, listener);
  g_assert (entry != NULL);

  gum_spinlock_acquire (&function_ctx->listener_lock);
  g_ptr_array_remove (function_ctx->listener_entries, entry);
  gum_spinlock_release (&function_ctx->listener_lock);

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

GumInvocationContext *
gum_interceptor_invocation_get_parent (GumInvocationContext * context)
{
  ListenerInvocationData * lid;

  lid = (ListenerInvocationData *) context->backend->user_data;
  if (lid == NULL)
    return NULL;

  return find_and_fill_parent_context_for_listener (lid->stack, lid->listener);
}

static GumInvocationBackend gum_interceptor_invocation_backend =
{
  _gum_interceptor_invocation_get_nth_argument,
  _gum_interceptor_invocation_replace_nth_argument,
  _gum_interceptor_invocation_get_return_value,
  gum_interceptor_invocation_get_parent,

  NULL
};

gboolean
_gum_function_context_on_enter (FunctionContext * function_ctx,
                                GumCpuContext * cpu_context,
                                gpointer * caller_ret_addr)
{
  gboolean will_trap_on_leave = FALSE;
  InterceptorThreadContext * interceptor_ctx;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = (guint32) *caller_ret_addr;
# else
  cpu_context->rip = (guint64) *caller_ret_addr;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = (guint32) *caller_ret_addr;
#else
# error Unsupported architecture
#endif

  interceptor_ctx = get_interceptor_thread_context ();
  if (interceptor_ctx->ignore_level == 0)
  {
    ThreadContextStackEntry * stack_entry;
    FunctionThreadContext * thread_ctx;
    GumInvocationContext * invocation_ctx;
    guint i;

    stack_entry = thread_context_stack_push (interceptor_ctx->stack,
        G_CALLBACK (function_ctx->function_address),
        *caller_ret_addr,
        NULL);
    *caller_ret_addr = function_ctx->on_leave_trampoline;
    will_trap_on_leave = TRUE;

    thread_ctx = get_function_thread_context (function_ctx);
    stack_entry->thread_ctx = thread_ctx;

    invocation_ctx = &stack_entry->invocation_context;
    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->backend = &thread_ctx->invocation_backend;

    for (i = 0; TRUE; i++)
    {
      ListenerEntry entry = { 0, };
      ListenerInvocationData listener_invocation_data;

      gum_spinlock_acquire (&function_ctx->listener_lock);
      if (i < function_ctx->listener_entries->len)
      {
        entry = *((ListenerEntry *)
            g_ptr_array_index (function_ctx->listener_entries, i));
        g_object_ref (entry.listener_instance);
      }
      gum_spinlock_release (&function_ctx->listener_lock);

      if (entry.listener_instance == NULL)
        break;

      invocation_ctx->instance_data = entry.function_instance_data;

      if (i < thread_ctx->listener_data_count)
      {
        invocation_ctx->thread_data = thread_ctx->listener_data[i];
      }
      else
      {
        if (entry.listener_interface->provide_thread_data != NULL)
        {
          invocation_ctx->thread_data =
              entry.listener_interface->provide_thread_data (
                  entry.listener_instance,
                  entry.function_instance_data,
                  get_current_thread_id ());
        }
        else
        {
          invocation_ctx->thread_data = NULL;
        }

        thread_ctx->listener_data_count++;
        g_assert (thread_ctx->listener_data_count <=
            G_N_ELEMENTS (thread_ctx->listener_data));

        thread_ctx->listener_data[i] = invocation_ctx->thread_data;
      }

      listener_invocation_data.stack = interceptor_ctx->stack;
      listener_invocation_data.listener = entry.listener_instance;
      thread_ctx->invocation_backend.user_data = &listener_invocation_data;

      entry.listener_interface->on_enter (entry.listener_instance,
          invocation_ctx);

      thread_ctx->listener_data[i] = invocation_ctx->thread_data;

      g_object_unref (entry.listener_instance);
    }

    stack_entry->cpu_context = *cpu_context;
    invocation_ctx->cpu_context = &stack_entry->cpu_context;
  }

#ifdef G_OS_WIN32
  SetLastError (previous_last_error);
#endif

  return will_trap_on_leave;
}

gpointer
_gum_function_context_on_leave (FunctionContext * function_ctx,
                                GumCpuContext * cpu_context)
{
  InterceptorThreadContext * interceptor_ctx;
  ThreadContextStackEntry * stack_entry;
  gpointer caller_ret_addr;
  GumInvocationContext * invocation_ctx;
  FunctionThreadContext * thread_ctx;
  guint i;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = thread_context_stack_peek_top (interceptor_ctx->stack);
  caller_ret_addr = stack_entry->caller_ret_addr;

  thread_ctx = stack_entry->thread_ctx;

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  invocation_ctx->backend = &thread_ctx->invocation_backend;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = (guint32) caller_ret_addr;
# else
  cpu_context->rip = (guint64) caller_ret_addr;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = (guint32) caller_ret_addr;
#else
# error Unsupported architecture
#endif

  for (i = 0; TRUE; i++)
  {
    ListenerEntry entry = { 0, };
    ListenerInvocationData listener_invocation_data;

    gum_spinlock_acquire (&function_ctx->listener_lock);
    if (i < function_ctx->listener_entries->len)
    {
      entry = *((ListenerEntry *)
        g_ptr_array_index (function_ctx->listener_entries, i));
      g_object_ref (entry.listener_instance);
    }
    gum_spinlock_release (&function_ctx->listener_lock);

    if (entry.listener_instance == NULL)
      break;

    invocation_ctx->instance_data = entry.function_instance_data;
    invocation_ctx->thread_data = thread_ctx->listener_data[i];

    listener_invocation_data.stack = interceptor_ctx->stack;
    listener_invocation_data.listener = entry.listener_instance;
    thread_ctx->invocation_backend.user_data = &listener_invocation_data;

    entry.listener_interface->on_leave (entry.listener_instance,
        invocation_ctx);

    thread_ctx->listener_data[i] = invocation_ctx->thread_data;

    g_object_unref (entry.listener_instance);
  }

  thread_context_stack_pop (interceptor_ctx->stack);

#ifdef G_OS_WIN32
  SetLastError (previous_last_error);
#endif

  return caller_ret_addr;
}

static GumInvocationContext *
find_and_fill_parent_context_for_listener (ThreadContextStack * stack,
                                           GumInvocationListener * listener)
{
  ThreadContextStackEntry * parent_entry;
  FunctionContext * parent_func_ctx;
  guint i;
  GumInvocationContext * parent_invocation_ctx = NULL;

  parent_entry = thread_context_stack_peek_directly_below_top (stack);
  if (parent_entry == NULL || parent_entry->thread_ctx == NULL)
    return NULL;

  parent_func_ctx = parent_entry->thread_ctx->function_ctx;

  gum_spinlock_acquire (&parent_func_ctx->listener_lock);

  for (i = 0; i != parent_func_ctx->listener_entries->len; i++)
  {
    ListenerEntry * entry = (ListenerEntry *)
        g_ptr_array_index (parent_func_ctx->listener_entries, i);

    if (entry->listener_instance == listener)
    {
      parent_invocation_ctx = &parent_entry->invocation_context;

      parent_invocation_ctx->instance_data = entry->function_instance_data;
      parent_invocation_ctx->thread_data =
          parent_entry->thread_ctx->listener_data[i];

      break;
    }
  }

  gum_spinlock_release (&parent_func_ctx->listener_lock);

  return parent_invocation_ctx;
}

gboolean
_gum_function_context_try_begin_invocation (GCallback function,
                                            gpointer caller_ret_addr,
                                            const GumCpuContext * cpu_context,
                                            gpointer user_data)
{
  ThreadContextStack * stack;
  ThreadContextStackEntry * entry;

  stack = get_interceptor_thread_context ()->stack;
  entry = thread_context_stack_peek_top (stack);
  if (entry != NULL && entry->invocation_context.function == function)
    return FALSE;

  entry = thread_context_stack_push (stack, function, caller_ret_addr,
      cpu_context);
  entry->invocation_context.instance_data = user_data;
  return TRUE;
}

gpointer
_gum_function_context_end_invocation (void)
{
  return thread_context_stack_pop (get_interceptor_thread_context ()->stack);
}

FunctionThreadContext *
get_function_thread_context (FunctionContext * function_ctx)
{
  guint32 thread_id;
  guint thread_count = function_ctx->thread_context_count;
  guint i;
  FunctionThreadContext * thread_ctx;

  thread_id = get_current_thread_id ();

  for (i = 0; i != thread_count; i++)
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

  thread_ctx->invocation_backend = gum_interceptor_invocation_backend;

  return thread_ctx;
}

static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = (InterceptorThreadContext *)
      GUM_TLS_KEY_GET_VALUE (_gum_interceptor_tls_key);
  if (context == NULL)
  {
    context = interceptor_thread_context_new ();

    gum_spinlock_acquire (&_gum_interceptor_thread_context_lock);
    gum_array_append_val (_gum_interceptor_thread_contexts, context);
    gum_spinlock_release (&_gum_interceptor_thread_context_lock);

    GUM_TLS_KEY_SET_VALUE (_gum_interceptor_tls_key, context);
  }

  return context;
}

static InterceptorThreadContext *
interceptor_thread_context_new (void)
{
  InterceptorThreadContext * context;

  context = gum_new0 (InterceptorThreadContext, 1);
  context->ignore_level = 0;
  context->stack = gum_array_sized_new (FALSE, TRUE,
      sizeof (ThreadContextStackEntry), GUM_MAX_CALL_DEPTH);

  return context;
}

static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  gum_array_free (context->stack, TRUE);
  gum_free (context);
}

static ThreadContextStackEntry *
thread_context_stack_push (ThreadContextStack * stack,
                           GCallback function,
                           gpointer caller_ret_addr,
                           const GumCpuContext * cpu_context)
{
  ThreadContextStackEntry * entry;
  GumInvocationContext * ctx;

  gum_array_set_size (stack, stack->len + 1);
  entry = (ThreadContextStackEntry *)
      &gum_array_index (stack, ThreadContextStackEntry, stack->len - 1);

  entry->caller_ret_addr = caller_ret_addr;

  ctx = &entry->invocation_context;
  ctx->function = function;

  ctx->backend = &gum_interceptor_invocation_backend;

  if (cpu_context != NULL)
  {
    entry->cpu_context = *cpu_context;
    ctx->cpu_context = &entry->cpu_context;
  }

  return entry;
}

static gpointer
thread_context_stack_pop (ThreadContextStack * stack)
{
  ThreadContextStackEntry * entry;
  gpointer caller_ret_addr;

  entry = (ThreadContextStackEntry *)
      &gum_array_index (stack, ThreadContextStackEntry, stack->len - 1);
  caller_ret_addr = entry->caller_ret_addr;
  gum_array_set_size (stack, stack->len - 1);

  return caller_ret_addr;
}

static ThreadContextStackEntry *
thread_context_stack_peek_top (ThreadContextStack * stack)
{
  if (stack->len == 0)
    return NULL;

  return &g_array_index (stack, ThreadContextStackEntry, stack->len - 1);
}

static ThreadContextStackEntry *
thread_context_stack_peek_directly_below_top (ThreadContextStack * stack)
{
  if (stack->len < 2)
    return NULL;

  return &g_array_index (stack, ThreadContextStackEntry, stack->len - 2);
}

static void
make_function_prologue_at_least_read_write (gpointer prologue_address)
{
  GumPageProtection prot;

#if defined (HAVE_DARWIN) && defined (HAVE_ARM)
  prot = GUM_PAGE_READ | GUM_PAGE_WRITE; /* RWX is not allowed */
#else
  prot = GUM_PAGE_RWX;
#endif

  gum_mprotect (prologue_address, 16, prot);
}

static void
make_function_prologue_read_execute (gpointer prologue_address)
{
  gum_mprotect (prologue_address, 16, GUM_PAGE_READ | GUM_PAGE_EXECUTE);
}

static gpointer
maybe_follow_redirect_at (GumInterceptor * self,
                          gpointer address)
{
  if (!is_patched_function (self, address))
  {
    gpointer target;

    target = _gum_interceptor_resolve_redirect (address);
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

static void
gum_function_context_wait_for_idle_trampoline (FunctionContext * ctx)
{
  if (ctx->trampoline_usage_counter == NULL)
    return;

  while (*ctx->trampoline_usage_counter != 0)
    g_thread_yield ();
  g_thread_yield ();
}

