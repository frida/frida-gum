/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "guminterceptor-priv.h"

#include "gumarray.h"
#include "gumhash.h"
#include "gummemory.h"
#include "gumtls.h"

#ifndef G_OS_WIN32
# include <errno.h>
#endif
#include <string.h>

#define GUM_INTERCEPTOR_CODE_SLICE_SIZE     452

#if defined (HAVE_DARWIN) && !defined (HAVE_ARM64)
# define GUM_INTERCEPTOR_FAST_TLS 1
#else
# define GUM_INTERCEPTOR_FAST_TLS 0
#endif

G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT);

#define GUM_INTERCEPTOR_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_INTERCEPTOR_UNLOCK() (g_mutex_unlock (&priv->mutex))

#ifdef HAVE_QNX
# define GUM_THREAD_SIDE_STACK_SIZE (2 * 1024 * 1024)
#endif

typedef struct _ListenerEntry            ListenerEntry;
typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _GumInvocationStackEntry  GumInvocationStackEntry;
typedef struct _ListenerDataSlot         ListenerDataSlot;
typedef struct _ListenerInvocationState  ListenerInvocationState;

struct _GumInterceptorPrivate
{
  GMutex mutex;

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

  GumInvocationStack * stack;

  GumArray * listener_data_slots;

#ifdef HAVE_QNX
  gpointer thread_side_stack;
#endif
};

struct _GumInvocationStackEntry
{
  gpointer trampoline_ret_addr;
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
static GumInvocationStackEntry * gum_invocation_stack_push (
    GumInvocationStack * stack, FunctionContext * function_ctx,
    gpointer caller_ret_addr, const GumCpuContext * cpu_context);
static gpointer gum_invocation_stack_pop (GumInvocationStack * stack);
static GumInvocationStackEntry * gum_invocation_stack_peek_top (
    GumInvocationStack * stack);

static void make_function_prologue_at_least_read_write (
    gpointer prologue_address);
static void make_function_prologue_read_execute (gpointer prologue_address);
static gpointer maybe_follow_redirect_at (GumInterceptor * self,
    gpointer address);

static gboolean is_patched_function (GumInterceptor * self,
    gpointer function_address);

static void gum_function_context_wait_for_idle_trampoline (
    FunctionContext * ctx);

#ifdef HAVE_QNX
static void gum_exec_callback_func_with_side_stack (
    GumInvocationListener * listener_instance,
    GumInvocationContext * invocation_ctx, gpointer func, gpointer side_stack);
#endif

static GMutex _gum_interceptor_mutex;
static GumInterceptor * _the_interceptor = NULL;

static GumTlsKey _gum_interceptor_context_key;
GumTlsKey _gum_interceptor_guard_key;

static GumSpinlock _gum_interceptor_thread_context_lock;
static GumArray * _gum_interceptor_thread_contexts;

static GumInvocationStack _gum_interceptor_empty_stack = { NULL, 0 };

static void
gum_interceptor_class_init (GumInterceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumInterceptorPrivate));

  object_class->finalize = gum_interceptor_finalize;
}

void
_gum_interceptor_init (void)
{
  GUM_TLS_KEY_INIT (&_gum_interceptor_context_key);
  GUM_TLS_KEY_INIT (&_gum_interceptor_guard_key);

  gum_spinlock_init (&_gum_interceptor_thread_context_lock);
  _gum_interceptor_thread_contexts = gum_array_new (FALSE, FALSE,
      sizeof (InterceptorThreadContext *));

  _gum_function_context_init ();
}

void
_gum_interceptor_deinit (void)
{
  guint i;

  _gum_function_context_deinit ();

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

  GUM_TLS_KEY_FREE (_gum_interceptor_context_key);
  GUM_TLS_KEY_FREE (_gum_interceptor_guard_key);
}

static void
gum_interceptor_init (GumInterceptor * self)
{
  GumInterceptorPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_INTERCEPTOR,
      GumInterceptorPrivate);

  priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  g_mutex_init (&priv->mutex);

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

  g_mutex_clear (&priv->mutex);

  gum_hash_table_unref (priv->monitored_function_by_address);
  gum_hash_table_unref (priv->replaced_function_by_address);

  gum_code_allocator_free (&priv->allocator);

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_mutex_lock (&_gum_interceptor_mutex);

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

  g_mutex_unlock (&_gum_interceptor_mutex);

  return interceptor;
}

static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  (void) data;

  g_mutex_lock (&_gum_interceptor_mutex);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_mutex_unlock (&_gum_interceptor_mutex);
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
  gpointer next_hop;

  GUM_INTERCEPTOR_LOCK ();

  while (TRUE)
  {
    next_hop = maybe_follow_redirect_at (self, function_address);
    if (next_hop != function_address)
      function_address = next_hop;
    else
      break;
  }

  replace_function_at (self, function_address, replacement_function,
      replacement_function_data);

  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_revert_function (GumInterceptor * self,
                                 gpointer function_address)
{
  GumInterceptorPrivate * priv = GUM_INTERCEPTOR_GET_PRIVATE (self);
  gpointer next_hop;

  GUM_INTERCEPTOR_LOCK ();

  while (TRUE)
  {
    next_hop = maybe_follow_redirect_at (self, function_address);
    if (next_hop != function_address)
      function_address = next_hop;
    else
      break;
  }

  revert_function_at (self, function_address);

  GUM_INTERCEPTOR_UNLOCK ();
}

GumInvocationContext *
gum_interceptor_get_current_invocation (void)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  if (entry == NULL)
    return NULL;

  return &entry->invocation_context;
}

GumInvocationStack *
gum_interceptor_get_current_stack (void)
{
  InterceptorThreadContext * context;

  context = (InterceptorThreadContext *)
      GUM_TLS_KEY_GET_VALUE (_gum_interceptor_context_key);
  if (context == NULL)
    return &_gum_interceptor_empty_stack;

  return context->stack;
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
  self->priv->selected_thread_id = gum_process_get_current_thread_id ();
}

void
gum_interceptor_unignore_other_threads (GumInterceptor * self)
{
  GumInterceptorPrivate * priv = self->priv;

  g_assert_cmpuint (priv->selected_thread_id,
      ==, gum_process_get_current_thread_id ());
  priv->selected_thread_id = 0;
}

gpointer
gum_invocation_stack_translate (GumInvocationStack * self,
                                gpointer return_address)
{
  guint i;

  for (i = 0; i != self->len; i++)
  {
    GumInvocationStackEntry * entry;

    entry = (GumInvocationStackEntry *)
        &gum_array_index (self, GumInvocationStackEntry, i);
    if (entry->trampoline_ret_addr == return_address)
      return entry->caller_ret_addr;
  }

  return return_address;
}

static FunctionContext *
intercept_function_at (GumInterceptor * self,
                       gpointer function_address)
{
  FunctionContext * ctx;

  ctx = function_context_new (self, function_address, &self->priv->allocator);

  ctx->listener_entries =
      gum_array_sized_new (FALSE, FALSE, sizeof (gpointer), 2);

  _gum_function_context_make_monitor_trampoline (ctx);
  if (!gum_query_is_rwx_supported ())
  {
    gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
        GUM_PAGE_RX);
  }

  make_function_prologue_at_least_read_write (function_address);
  _gum_function_context_activate_trampoline (ctx);
  make_function_prologue_read_execute (function_address);

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
  if (!gum_query_is_rwx_supported ())
  {
    gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
        GUM_PAGE_RX);
  }

  make_function_prologue_at_least_read_write (function_address);
  _gum_function_context_activate_trampoline (ctx);
  make_function_prologue_read_execute (function_address);

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
      function_context_destroy (function_ctx);

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
    make_function_prologue_at_least_read_write (function_ctx->function_address);
    _gum_function_context_deactivate_trampoline (function_ctx);
    make_function_prologue_read_execute (function_ctx->function_address);

    gum_function_context_wait_for_idle_trampoline (function_ctx);
    _gum_function_context_destroy_trampoline (function_ctx);
  }

  if (function_ctx->listener_entries != NULL)
    gum_array_free (function_ctx->listener_entries, TRUE);

  gum_free (function_ctx);
}

static void
function_context_add_listener (FunctionContext * function_ctx,
                               GumInvocationListener * listener,
                               gpointer function_data)
{
  ListenerEntry * entry;

  entry = gum_new (ListenerEntry, 1);
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_INTERFACE (listener);
  entry->listener_instance = listener;
  entry->function_data = function_data;

  gum_array_append_val (function_ctx->listener_entries, entry);
}

static void
function_context_remove_listener (FunctionContext * function_ctx,
                                  GumInvocationListener * listener)
{
  ListenerEntry * entry;
  guint i;

  entry = function_context_find_listener_entry (function_ctx, listener);
  g_assert (entry != NULL);

  for (i = 0; i < function_ctx->listener_entries->len; i++)
  {
    ListenerEntry * cur =
        gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);
    if (cur == entry)
    {
      gum_array_remove_index (function_ctx->listener_entries, i);
      break;
    }
  }

  gum_free (entry);
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
    ListenerEntry * entry =
        gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);

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
  GumInterceptor * self = function_ctx->interceptor;
  GumInterceptorPrivate * priv = self->priv;
  gint system_error;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave = FALSE;
  InterceptorThreadContext * interceptor_ctx = NULL;

#ifdef G_OS_WIN32
  system_error = GetLastError ();
#else
  system_error = errno;
#endif

#if !GUM_INTERCEPTOR_FAST_TLS
  if (GUM_TLS_KEY_GET_VALUE (_gum_interceptor_guard_key) == self)
    return FALSE;
  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, self);
#endif

  if (G_UNLIKELY (priv->selected_thread_id != 0))
  {
    invoke_listeners =
        gum_process_get_current_thread_id () == priv->selected_thread_id;
  }

  if (G_LIKELY (invoke_listeners))
  {
    interceptor_ctx = get_interceptor_thread_context ();
    invoke_listeners = (interceptor_ctx->ignore_level == 0);
  }

  if (G_LIKELY (invoke_listeners))
  {
    GumInvocationStackEntry * stack_entry;
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
#elif defined (HAVE_ARM64)
    cpu_context->pc = (guint64) *caller_ret_addr;
#else
# error Unsupported architecture
#endif

    stack_entry = gum_invocation_stack_push (interceptor_ctx->stack,
        function_ctx, *caller_ret_addr, NULL);

    invocation_ctx = &stack_entry->invocation_context;
    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->system_error = system_error;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    for (i = 0; i != function_ctx->listener_entries->len; i++)
    {
      ListenerEntry * entry;
      ListenerInvocationState state;

      entry =
          gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);

      state.point_cut = GUM_POINT_ENTER;
      state.entry = entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

#ifdef HAVE_QNX
      gum_exec_callback_func_with_side_stack (entry->listener_instance,
          invocation_ctx, entry->listener_interface->on_enter,
          interceptor_ctx->thread_side_stack + GUM_THREAD_SIDE_STACK_SIZE - 4);
#else
      entry->listener_interface->on_enter (entry->listener_instance,
          invocation_ctx);
#endif
    }

#ifdef G_OS_WIN32
    SetLastError (invocation_ctx->system_error);
#else
    errno = invocation_ctx->system_error;
#endif

    *caller_ret_addr = function_ctx->on_leave_trampoline;
    will_trap_on_leave = TRUE;
  }

#if !GUM_INTERCEPTOR_FAST_TLS
  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, NULL);
#endif

  return will_trap_on_leave;
}

void
_gum_function_context_on_leave (FunctionContext * function_ctx,
                                GumCpuContext * cpu_context,
                                gpointer * caller_ret_addr)
{
  gint system_error;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx;
  guint i;

#ifdef G_OS_WIN32
  system_error = GetLastError ();
#else
  system_error = errno;
#endif

#if !GUM_INTERCEPTOR_FAST_TLS
  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, function_ctx->interceptor);
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  *caller_ret_addr = stack_entry->caller_ret_addr;

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  invocation_ctx->system_error = system_error;
  invocation_ctx->backend = &interceptor_ctx->listener_backend;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = (guint32) *caller_ret_addr;
# else
  cpu_context->rip = (guint64) *caller_ret_addr;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = (guint32) *caller_ret_addr;
#elif defined (HAVE_ARM64)
  cpu_context->pc = (guint64) *caller_ret_addr;
#else
# error Unsupported architecture
#endif

  for (i = 0; i != function_ctx->listener_entries->len; i++)
  {
    ListenerEntry * entry;
    ListenerInvocationState state;

    entry =
        gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);

    state.point_cut = GUM_POINT_LEAVE;
    state.entry = entry;
    state.interceptor_ctx = interceptor_ctx;
    state.invocation_data = stack_entry->listener_invocation_data[i];
    invocation_ctx->backend->data = &state;

#ifdef HAVE_QNX
    gum_exec_callback_func_with_side_stack (entry->listener_instance,
        invocation_ctx, entry->listener_interface->on_leave,
        interceptor_ctx->thread_side_stack + GUM_THREAD_SIDE_STACK_SIZE - 4);
#else
    entry->listener_interface->on_leave (entry->listener_instance,
        invocation_ctx);
#endif
  }

#ifdef G_OS_WIN32
  SetLastError (invocation_ctx->system_error);
#else
  errno = invocation_ctx->system_error;
#endif

  gum_invocation_stack_pop (interceptor_ctx->stack);

#if !GUM_INTERCEPTOR_FAST_TLS
  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, NULL);
#endif
}

#ifdef HAVE_QNX
__attribute__ ((naked)) static void
gum_exec_callback_func_with_side_stack (
    GumInvocationListener * listener_instance,
    GumInvocationContext * invocation_ctx,
    gpointer func,
    gpointer side_stack)
{
  __asm__ ("stmfd sp!, {r4, lr}\n\t"
      "mov r4, sp\n\t"
      "mov sp, r3\n\t"
      "blx r2\n\t"
      "mov sp, r4\n\t"
      "ldmfd sp!, {r4, pc}");
}
#endif

gboolean
_gum_function_context_try_begin_invocation (FunctionContext * function_ctx,
                                            gpointer caller_ret_addr,
                                            const GumCpuContext * cpu_context)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStack * stack;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  entry = gum_invocation_stack_peek_top (stack);
  if (entry != NULL &&
      entry->invocation_context.function == function_ctx->function_address)
  {
    return FALSE;
  }

  entry = gum_invocation_stack_push (stack, function_ctx, caller_ret_addr,
      cpu_context);

  entry->invocation_context.backend = &interceptor_ctx->replacement_backend;
  entry->invocation_context.backend->data =
      function_ctx->replacement_function_data;

  return TRUE;
}

gpointer
_gum_function_context_end_invocation (void)
{
  return gum_invocation_stack_pop (get_interceptor_thread_context ()->stack);
}

static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = (InterceptorThreadContext *)
      GUM_TLS_KEY_GET_VALUE (_gum_interceptor_context_key);
  if (context == NULL)
  {
    context = interceptor_thread_context_new ();

    gum_spinlock_acquire (&_gum_interceptor_thread_context_lock);
    gum_array_append_val (_gum_interceptor_thread_contexts, context);
    gum_spinlock_release (&_gum_interceptor_thread_context_lock);

    GUM_TLS_KEY_SET_VALUE (_gum_interceptor_context_key, context);
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

static GumThreadId
gum_interceptor_invocation_get_thread_id (GumInvocationContext * context)
{
  (void) context;

  return gum_process_get_current_thread_id ();
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
  _gum_interceptor_invocation_replace_return_value,

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
  _gum_interceptor_invocation_replace_return_value,

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
      sizeof (GumInvocationStackEntry), GUM_MAX_CALL_DEPTH);

  context->listener_data_slots = gum_array_sized_new (FALSE, TRUE,
      sizeof (ListenerDataSlot), GUM_MAX_LISTENERS_PER_FUNCTION);

#ifdef HAVE_QNX
  context->thread_side_stack = gum_alloc_n_pages (
      GUM_THREAD_SIDE_STACK_SIZE / gum_query_page_size (), GUM_PAGE_RW);
#endif

  return context;
}

static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  gum_array_free (context->listener_data_slots, TRUE);

  gum_array_free (context->stack, TRUE);

#ifdef HAVE_QNX
  gum_free_pages (context->thread_side_stack);
#endif

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

static GumInvocationStackEntry *
gum_invocation_stack_push (GumInvocationStack * stack,
                           FunctionContext * function_ctx,
                           gpointer caller_ret_addr,
                           const GumCpuContext * cpu_context)
{
  GumInvocationStackEntry * entry;
  GumInvocationContext * ctx;

  gum_array_set_size (stack, stack->len + 1);
  entry = (GumInvocationStackEntry *)
      &gum_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  entry->trampoline_ret_addr = function_ctx->on_leave_trampoline;
  entry->caller_ret_addr = caller_ret_addr;

  ctx = &entry->invocation_context;
  ctx->function =
      GUM_POINTER_TO_FUNCPTR (GCallback, function_ctx->function_address);

  ctx->backend = NULL;

  if (cpu_context != NULL)
  {
    entry->cpu_context = *cpu_context;
    ctx->cpu_context = &entry->cpu_context;
  }

  return entry;
}

static gpointer
gum_invocation_stack_pop (GumInvocationStack * stack)
{
  GumInvocationStackEntry * entry;
  gpointer caller_ret_addr;

  entry = (GumInvocationStackEntry *)
      &gum_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  caller_ret_addr = entry->caller_ret_addr;
  gum_array_set_size (stack, stack->len - 1);

  return caller_ret_addr;
}

static GumInvocationStackEntry *
gum_invocation_stack_peek_top (GumInvocationStack * stack)
{
  if (stack->len == 0)
    return NULL;

  return &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
}

static void
make_function_prologue_at_least_read_write (gpointer prologue_address)
{
  GumPageProtection prot;

  prot = gum_query_is_rwx_supported () ? GUM_PAGE_RWX : GUM_PAGE_RW;

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

static void
gum_function_context_wait_for_idle_trampoline (FunctionContext * ctx)
{
  if (ctx->trampoline_usage_counter == NULL)
    return;

  while (*ctx->trampoline_usage_counter != 0)
    g_thread_yield ();
  g_thread_yield ();
}
