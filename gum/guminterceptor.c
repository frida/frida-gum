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

typedef struct _ListenerEntry            ListenerEntry;
typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef GumArray                         ThreadContextStack;
typedef struct _ThreadContextStackEntry  ThreadContextStackEntry;
typedef struct _ListenerDataSlot         ListenerDataSlot;
typedef struct _ListenerInvocationState  ListenerInvocationState;

struct _GumInterceptorPrivate
{
  GMutex * mutex;

  GumHashTable * monitored_function_by_address;
  GumHashTable * replaced_function_by_address;

  GumCodeAllocator allocator;

  volatile guint selected_thread_id;
};

struct _ListenerEntry
{
  GumInvocationListenerIface * listener_interface;
  GumInvocationListener * listener_instance;
  gpointer function_data;
};

struct _InterceptorThreadContext
{
  GumInvocationBackend listener_backend;
  GumInvocationBackend replacement_backend;

  guint ignore_level;

  ThreadContextStack * stack;

  GumArray * listener_data_slots;
};

struct _ThreadContextStackEntry
{
  gpointer caller_ret_addr;
  GumInvocationContext invocation_context;
  GumCpuContext cpu_context;
  guint8 listener_invocation_data[GUM_MAX_LISTENERS_PER_FUNCTION][GUM_MAX_LISTENER_DATA];
};

struct _ListenerDataSlot
{
  GumInvocationListener * owner;
  guint8 data[GUM_MAX_LISTENER_DATA];
};

struct _ListenerInvocationState
{
  GumPointCut point_cut;
  ListenerEntry * entry;
  InterceptorThreadContext * interceptor_ctx;
  guint8 * invocation_data;
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
static FunctionContext * function_context_new (GumInterceptor * interceptor,
    gpointer function_address, GumCodeAllocator * allocator);
static void function_context_destroy (FunctionContext * function_ctx);
static void function_context_add_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener, gpointer function_data);
static void function_context_remove_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static gboolean function_context_has_listener (FunctionContext * function_ctx,
    GumInvocationListener * listener);
static ListenerEntry * function_context_find_listener_entry (
    FunctionContext * function_ctx, GumInvocationListener * listener);

static InterceptorThreadContext * get_interceptor_thread_context (void);
static InterceptorThreadContext * interceptor_thread_context_new (void);
static void interceptor_thread_context_destroy (
    InterceptorThreadContext * context);
static gpointer interceptor_thread_context_get_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener,
    gsize required_size);
static void interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener);
static ThreadContextStackEntry * thread_context_stack_push (
    ThreadContextStack * stack, GCallback function, gpointer caller_ret_addr,
    const GumCpuContext * cpu_context);
static gpointer thread_context_stack_pop (ThreadContextStack * stack);
static ThreadContextStackEntry * thread_context_stack_peek_top (
    ThreadContextStack * stack);

static void make_function_prologue_at_least_read_write (
    gpointer prologue_address);
static void make_function_prologue_read_execute (gpointer prologue_address);
static gpointer maybe_follow_redirect_at (GumInterceptor * self,
    gpointer address);

static gboolean is_patched_function (GumInterceptor * self,
    gpointer function_address);

static guint gum_get_current_thread_id (void);

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
    _the_interceptor =
        GUM_INTERCEPTOR_CAST (g_object_new (GUM_TYPE_INTERCEPTOR, NULL));
    g_object_weak_ref (G_OBJECT (_the_interceptor),
        the_interceptor_weak_notify, NULL);

    interceptor = _the_interceptor;
  }

  g_static_mutex_unlock (&_gum_interceptor_mutex);

  return interceptor;
}

static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  (void) data;

  g_static_mutex_lock (&_gum_interceptor_mutex);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_static_mutex_unlock (&_gum_interceptor_mutex);
}

GumAttachReturn
gum_interceptor_attach_listener (GumInterceptor * self,
                                 gpointer function_address,
                                 GumInvocationListener * listener,
                                 gpointer listener_function_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  GumAttachReturn result = GUM_ATTACH_OK;
  gpointer next_hop;
  FunctionContext * function_ctx;

  gum_interceptor_ignore_current_thread (self);
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
      listener_function_data);

beach:
  GUM_INTERCEPTOR_UNLOCK ();
  gum_interceptor_unignore_current_thread (self);

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
  guint i;

  gum_interceptor_ignore_current_thread (self);
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

  /*
   * We don't do any locking here because this array is grow-only, so we won't
   * do anything else than just mark the slot as available.
   */
  for (i = 0; i != _gum_interceptor_thread_contexts->len; i++)
  {
    InterceptorThreadContext * interceptor_ctx;

    interceptor_ctx = (InterceptorThreadContext *) gum_array_index (
        _gum_interceptor_thread_contexts, InterceptorThreadContext *, i);
    interceptor_thread_context_forget_listener_data (interceptor_ctx,
        listener);
  }

  GUM_INTERCEPTOR_UNLOCK ();
  gum_interceptor_unignore_current_thread (self);
}

void
gum_interceptor_replace_function (GumInterceptor * self,
                                  gpointer function_address,
                                  gpointer replacement_function,
                                  gpointer replacement_function_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);

  GUM_INTERCEPTOR_LOCK ();

  function_address = maybe_follow_redirect_at (self, function_address);

  make_function_prologue_at_least_read_write (function_address);
  replace_function_at (self, function_address, replacement_function,
      replacement_function_data);
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
gum_interceptor_ignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  (void) self;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level++;
}

void
gum_interceptor_unignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  (void) self;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level--;
}

void
gum_interceptor_ignore_other_threads (GumInterceptor * self)
{
  self->priv->selected_thread_id = gum_get_current_thread_id ();
}

void
gum_interceptor_unignore_other_threads (GumInterceptor * self)
{
  GumInterceptorPrivate * priv = self->priv;

  g_assert_cmpuint (priv->selected_thread_id, ==, gum_get_current_thread_id ());
  priv->selected_thread_id = 0;
}

static FunctionContext *
intercept_function_at (GumInterceptor * self,
                       gpointer function_address)
{
  FunctionContext * ctx;

  ctx = function_context_new (self, function_address, &self->priv->allocator);

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
                     gpointer replacement_function,
                     gpointer replacement_function_data)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  FunctionContext * ctx;

  ctx = function_context_new (self, function_address, &priv->allocator);

  ctx->replacement_function_data = replacement_function_data;

  _gum_function_context_make_replace_trampoline (ctx, replacement_function);
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
function_context_new (GumInterceptor * interceptor,
                      gpointer function_address,
                      GumCodeAllocator * allocator)
{
  FunctionContext * ctx;

  ctx = gum_new0 (FunctionContext, 1);
  ctx->interceptor = interceptor;
  ctx->function_address = function_address;

  ctx->allocator = allocator;

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

  gum_free (function_ctx);
}

static void
function_context_add_listener (FunctionContext * function_ctx,
                               GumInvocationListener * listener,
                               gpointer function_data)
{
  ListenerEntry * entry;

  entry = g_new (ListenerEntry, 1);
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_INTERFACE (listener);
  entry->listener_instance = listener;
  entry->function_data = function_data;

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

gboolean
_gum_function_context_on_enter (FunctionContext * function_ctx,
                                GumCpuContext * cpu_context,
                                gpointer * caller_ret_addr)
{
  GumInterceptorPrivate * priv = function_ctx->interceptor->priv;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave = FALSE;
  InterceptorThreadContext * interceptor_ctx = NULL;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

  g_assert_cmpint (GPOINTER_TO_SIZE (&function_ctx) % 16, ==, 0);

  if (G_UNLIKELY (priv->selected_thread_id != 0))
  {
    invoke_listeners = gum_get_current_thread_id () == priv->selected_thread_id;
  }

  if (G_LIKELY (invoke_listeners))
  {
    interceptor_ctx = get_interceptor_thread_context ();
    invoke_listeners = (interceptor_ctx->ignore_level == 0);
  }

  if (G_LIKELY (invoke_listeners))
  {
    ThreadContextStackEntry * stack_entry;
    GumInvocationContext * invocation_ctx;
    guint i;

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

    stack_entry = thread_context_stack_push (interceptor_ctx->stack,
        GUM_POINTER_TO_FUNCPTR (GCallback, function_ctx->function_address),
        *caller_ret_addr,
        NULL);
    *caller_ret_addr = function_ctx->on_leave_trampoline;
    will_trap_on_leave = TRUE;

    invocation_ctx = &stack_entry->invocation_context;
    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    for (i = 0; i != function_ctx->listener_entries->len; i++)
    {
      ListenerEntry * entry;
      ListenerInvocationState state;

      entry = (ListenerEntry *)
          g_ptr_array_index (function_ctx->listener_entries, i);

      state.point_cut = GUM_POINT_ENTER;
      state.entry = entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

      entry->listener_interface->on_enter (entry->listener_instance,
          invocation_ctx);
    }
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
  guint i;
#ifdef G_OS_WIN32
  DWORD previous_last_error;

  previous_last_error = GetLastError ();
#endif

  g_assert_cmpint (GPOINTER_TO_SIZE (&function_ctx) % 16, ==, 0);

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = thread_context_stack_peek_top (interceptor_ctx->stack);
  caller_ret_addr = stack_entry->caller_ret_addr;

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  invocation_ctx->backend = &interceptor_ctx->listener_backend;

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

  for (i = 0; i != function_ctx->listener_entries->len; i++)
  {
    ListenerEntry * entry;
    ListenerInvocationState state;

    entry = (ListenerEntry *)
        g_ptr_array_index (function_ctx->listener_entries, i);

    state.point_cut = GUM_POINT_LEAVE;
    state.entry = entry;
    state.interceptor_ctx = interceptor_ctx;
    state.invocation_data = stack_entry->listener_invocation_data[i];
    invocation_ctx->backend->data = &state;

    entry->listener_interface->on_leave (entry->listener_instance,
        invocation_ctx);
  }

  thread_context_stack_pop (interceptor_ctx->stack);

#ifdef G_OS_WIN32
  SetLastError (previous_last_error);
#endif

  return caller_ret_addr;
}

gboolean
_gum_function_context_try_begin_invocation (FunctionContext * function_ctx,
                                            gpointer caller_ret_addr,
                                            const GumCpuContext * cpu_context)
{
  InterceptorThreadContext * interceptor_ctx;
  ThreadContextStack * stack;
  ThreadContextStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  entry = thread_context_stack_peek_top (stack);
  if (entry != NULL &&
      entry->invocation_context.function == function_ctx->function_address)
  {
    return FALSE;
  }

  entry = thread_context_stack_push (stack,
      GUM_POINTER_TO_FUNCPTR (GCallback, function_ctx->function_address),
      caller_ret_addr, cpu_context);

  entry->invocation_context.backend = &interceptor_ctx->replacement_backend;
  entry->invocation_context.backend->data =
      function_ctx->replacement_function_data;

  return TRUE;
}

gpointer
_gum_function_context_end_invocation (void)
{
  return thread_context_stack_pop (get_interceptor_thread_context ()->stack);
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

static GumPointCut
gum_interceptor_invocation_get_listener_point_cut (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *) context->backend->data)->point_cut;
}

static GumPointCut
gum_interceptor_invocation_get_replacement_point_cut (
    GumInvocationContext * context)
{
  (void) context;

  return GUM_POINT_ENTER;
}

static guint
gum_interceptor_invocation_get_thread_id (GumInvocationContext * context)
{
  (void) context;

  return gum_get_current_thread_id ();
}

static gpointer
gum_interceptor_invocation_get_listener_thread_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data =
      (ListenerInvocationState *) context->backend->data;

  return interceptor_thread_context_get_listener_data (data->interceptor_ctx,
      data->entry->listener_instance, required_size);
}

static gpointer
gum_interceptor_invocation_get_listener_function_data (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *)
      context->backend->data)->entry->function_data;
}

static gpointer
gum_interceptor_invocation_get_listener_function_invocation_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data;

  data = (ListenerInvocationState *) context->backend->data;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  return data->invocation_data;
}

static gpointer
gum_interceptor_invocation_get_replacement_function_data (
    GumInvocationContext * context)
{
  return context->backend->data;
}

static const GumInvocationBackend
gum_interceptor_listener_invocation_backend =
{
  gum_interceptor_invocation_get_listener_point_cut,

  _gum_interceptor_invocation_get_nth_argument,
  _gum_interceptor_invocation_replace_nth_argument,
  _gum_interceptor_invocation_get_return_value,

  gum_interceptor_invocation_get_thread_id,

  gum_interceptor_invocation_get_listener_thread_data,
  gum_interceptor_invocation_get_listener_function_data,
  gum_interceptor_invocation_get_listener_function_invocation_data,

  NULL,

  NULL
};

static const GumInvocationBackend
gum_interceptor_replacement_invocation_backend =
{
  gum_interceptor_invocation_get_replacement_point_cut,

  _gum_interceptor_invocation_get_nth_argument,
  _gum_interceptor_invocation_replace_nth_argument,
  _gum_interceptor_invocation_get_return_value,

  gum_interceptor_invocation_get_thread_id,

  NULL,
  NULL,
  NULL,

  gum_interceptor_invocation_get_replacement_function_data,

  NULL
};

static InterceptorThreadContext *
interceptor_thread_context_new (void)
{
  InterceptorThreadContext * context;

  context = gum_new0 (InterceptorThreadContext, 1);

  context->listener_backend =
      gum_interceptor_listener_invocation_backend;
  context->replacement_backend =
      gum_interceptor_replacement_invocation_backend;

  context->ignore_level = 0;

  context->stack = gum_array_sized_new (FALSE, TRUE,
      sizeof (ThreadContextStackEntry), GUM_MAX_CALL_DEPTH);

  context->listener_data_slots = gum_array_sized_new (FALSE, TRUE,
      sizeof (ListenerDataSlot), GUM_MAX_LISTENERS_PER_FUNCTION);

  return context;
}

static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  gum_array_free (context->listener_data_slots, TRUE);

  gum_array_free (context->stack, TRUE);

  gum_free (context);
}

static gpointer
interceptor_thread_context_get_listener_data (InterceptorThreadContext * self,
                                              GumInvocationListener * listener,
                                              gsize required_size)
{
  guint i;
  ListenerDataSlot * available_slot = NULL;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &gum_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
      return slot->data;
    else if (slot->owner == NULL)
      available_slot = slot;
  }

  if (available_slot == NULL)
  {
    gum_array_set_size (self->listener_data_slots,
        self->listener_data_slots->len + 1);
    available_slot = &gum_array_index (self->listener_data_slots,
        ListenerDataSlot, self->listener_data_slots->len - 1);
  }
  else
  {
    memset (available_slot->data, 0, sizeof (available_slot->data));
  }

  available_slot->owner = listener;

  return available_slot->data;
}

static void
interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self,
    GumInvocationListener * listener)
{
  guint i;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &gum_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
    {
      slot->owner = NULL;
      return;
    }
  }
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

  ctx->backend = NULL;

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
gum_get_current_thread_id (void)
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
