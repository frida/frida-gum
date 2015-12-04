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

#ifdef HAVE_ARM64
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 256
#else
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 548
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

  GumHashTable * function_by_address;

  GumInterceptorBackend * backend;
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
  gboolean calling_replacement;
#ifdef HAVE_QNX
  gpointer saved_original_stack;
#endif
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

static void gum_interceptor_dispose (GObject * object);
static void gum_interceptor_finalize (GObject * object);

static void the_interceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static GumFunctionContext * gum_interceptor_instrument (GumInterceptor * self,
    gpointer function_address);
static GumFunctionContext * gum_function_context_new (
    GumInterceptor * interceptor, gpointer function_address,
    GumCodeAllocator * allocator);
static void gum_function_context_destroy (GumFunctionContext * function_ctx);
static gboolean gum_function_context_try_destroy (
    GumFunctionContext * function_ctx);
static void gum_function_context_add_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener,
    gpointer function_data);
static void gum_function_context_remove_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static gboolean gum_function_context_has_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry * gum_function_context_find_listener_entry (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);

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
    GumInvocationStack * stack, GumFunctionContext * function_ctx,
    gpointer caller_ret_addr);
static gpointer gum_invocation_stack_pop (GumInvocationStack * stack);
static GumInvocationStackEntry * gum_invocation_stack_peek_top (
    GumInvocationStack * stack);

static gpointer gum_interceptor_resolve (GumInterceptor * self,
    gpointer address);
static gboolean gum_interceptor_has (GumInterceptor * self,
    gpointer function_address);
static void gum_function_context_wait_for_idle_trampoline (
    GumFunctionContext * ctx);

static void make_function_prologue_at_least_read_write (
    gpointer prologue_address);
static void make_function_prologue_read_execute (gpointer prologue_address);

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

  object_class->dispose = gum_interceptor_dispose;
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
}

void
_gum_interceptor_deinit (void)
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

  GUM_TLS_KEY_FREE (_gum_interceptor_context_key);
  GUM_TLS_KEY_FREE (_gum_interceptor_guard_key);
}

static void
gum_interceptor_init (GumInterceptor * self)
{
  GumInterceptorPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_INTERCEPTOR,
      GumInterceptorPrivate);

  g_mutex_init (&priv->mutex);

  priv->function_by_address = gum_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);

  gum_code_allocator_init (&priv->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE);
  priv->backend = _gum_interceptor_backend_create (&priv->allocator);
}

static void
gum_interceptor_dispose (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = self->priv;
  GumHashTableIter iter;
  GumFunctionContext * function_ctx;

  gum_hash_table_iter_init (&iter, priv->function_by_address);
  while (gum_hash_table_iter_next (&iter, NULL, (gpointer *) &function_ctx))
  {
    gum_function_context_destroy (function_ctx);
    gum_hash_table_iter_remove (&iter);
  }

  G_OBJECT_CLASS (gum_interceptor_parent_class)->dispose (object);
}

static void
gum_interceptor_finalize (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = self->priv;

  _gum_interceptor_backend_destroy (priv->backend);

  g_mutex_clear (&priv->mutex);

  gum_hash_table_unref (priv->function_by_address);

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
  GumInterceptorPrivate * priv = self->priv;
  GumAttachReturn result = GUM_ATTACH_OK;
  GumFunctionContext * function_ctx;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK ();

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = gum_interceptor_instrument (self, function_address);
  if (function_ctx == NULL)
    goto wrong_signature;

  if (gum_function_context_has_listener (function_ctx, listener))
    goto already_attached;

  gum_function_context_add_listener (function_ctx, listener,
      listener_function_data);

  goto beach;

wrong_signature:
  {
    result = GUM_ATTACH_WRONG_SIGNATURE;
    goto beach;
  }
already_attached:
  {
    result = GUM_ATTACH_ALREADY_ATTACHED;
    goto beach;
  }
beach:
  {
    GUM_INTERCEPTOR_UNLOCK ();
    gum_interceptor_unignore_current_thread (self);

    return result;
  }
}

void
gum_interceptor_detach_listener (GumInterceptor * self,
                                 GumInvocationListener * listener)
{
  GumInterceptorPrivate * priv = self->priv;
  GumHashTableIter iter;
  GumFunctionContext * function_ctx;
  guint i;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK ();

  gum_hash_table_iter_init (&iter, priv->function_by_address);
  while (gum_hash_table_iter_next (&iter, NULL, (gpointer *) &function_ctx))
  {
    if (gum_function_context_has_listener (function_ctx, listener))
    {
      gum_function_context_remove_listener (function_ctx, listener);

      if (gum_function_context_try_destroy (function_ctx))
      {
        gum_hash_table_iter_remove (&iter);
      }
    }
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

GumReplaceReturn
gum_interceptor_replace_function (GumInterceptor * self,
                                  gpointer function_address,
                                  gpointer replacement_function,
                                  gpointer replacement_function_data)
{
  GumInterceptorPrivate * priv = self->priv;
  GumReplaceReturn result = GUM_REPLACE_OK;
  GumFunctionContext * function_ctx;

  GUM_INTERCEPTOR_LOCK ();

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = gum_interceptor_instrument (self, function_address);
  if (function_ctx == NULL)
    goto wrong_signature;

  if (function_ctx->replacement_function != NULL)
    goto already_replaced;

  function_ctx->replacement_function_data = replacement_function_data;
  function_ctx->replacement_function = replacement_function;

  goto beach;

wrong_signature:
  {
    result = GUM_REPLACE_WRONG_SIGNATURE;
    goto beach;
  }
already_replaced:
  {
    result = GUM_REPLACE_ALREADY_REPLACED;
    goto beach;
  }
beach:
  {
    GUM_INTERCEPTOR_UNLOCK ();

    return result;
  }
}

void
gum_interceptor_revert_function (GumInterceptor * self,
                                 gpointer function_address)
{
  GumInterceptorPrivate * priv = self->priv;
  GumFunctionContext * function_ctx;

  GUM_INTERCEPTOR_LOCK ();

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = (GumFunctionContext *) gum_hash_table_lookup (
      priv->function_by_address, function_address);
  if (function_ctx == NULL)
    goto beach;

  function_ctx->replacement_function = NULL;
  function_ctx->replacement_function_data = NULL;

  if (gum_function_context_try_destroy (function_ctx))
  {
    gum_hash_table_remove (priv->function_by_address, function_address);
  }

beach:
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

static GumFunctionContext *
gum_interceptor_instrument (GumInterceptor * self,
                            gpointer function_address)
{
  GumInterceptorPrivate * priv = self->priv;
  GumFunctionContext * ctx;

  ctx = (GumFunctionContext *) gum_hash_table_lookup (priv->function_by_address,
      function_address);
  if (ctx != NULL)
    return ctx;

  if (!_gum_interceptor_backend_can_intercept (priv->backend,
      function_address))
    return NULL;

  ctx = gum_function_context_new (self, function_address, &priv->allocator);
  if (ctx == NULL)
    return NULL;

  if (!_gum_interceptor_backend_create_trampoline (priv->backend, ctx))
  {
    gum_function_context_destroy (ctx);
    return NULL;
  }

  if (!gum_query_is_rwx_supported ())
  {
    gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
        GUM_PAGE_RX);
  }

  make_function_prologue_at_least_read_write (function_address);
  _gum_interceptor_backend_activate_trampoline (priv->backend, ctx);
  make_function_prologue_read_execute (function_address);
  _gum_interceptor_backend_commit_trampoline (priv->backend, ctx);

  gum_hash_table_insert (priv->function_by_address, function_address, ctx);

  return ctx;
}

static GumFunctionContext *
gum_function_context_new (GumInterceptor * interceptor,
                          gpointer function_address,
                          GumCodeAllocator * allocator)
{
  GumFunctionContext * ctx;

  ctx = gum_new0 (GumFunctionContext, 1);
  ctx->interceptor = interceptor;
  ctx->function_address = function_address;

  ctx->listener_entries =
      gum_array_sized_new (FALSE, FALSE, sizeof (gpointer), 2);

  ctx->allocator = allocator;

  return ctx;
}

static void
gum_function_context_destroy (GumFunctionContext * function_ctx)
{
  guint i;

  if (function_ctx->trampoline_slice != NULL)
  {
    GumInterceptorBackend * backend = function_ctx->interceptor->priv->backend;

    make_function_prologue_at_least_read_write (function_ctx->function_address);
    _gum_interceptor_backend_deactivate_trampoline (backend, function_ctx);
    make_function_prologue_read_execute (function_ctx->function_address);
    _gum_interceptor_backend_commit_trampoline (backend, function_ctx);

    gum_function_context_wait_for_idle_trampoline (function_ctx);
    _gum_interceptor_backend_destroy_trampoline (backend, function_ctx);
  }

  for (i = 0; i != function_ctx->listener_entries->len; i++)
  {
    ListenerEntry * cur =
        gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);
    gum_free (cur);
  }
  gum_array_free (function_ctx->listener_entries, TRUE);

  gum_free (function_ctx);
}

static gboolean
gum_function_context_try_destroy (GumFunctionContext * function_ctx)
{
  if (function_ctx->replacement_function != NULL ||
      function_ctx->listener_entries->len > 0)
    return FALSE;

  gum_function_context_destroy (function_ctx);
  return TRUE;
}

static void
gum_function_context_add_listener (GumFunctionContext * function_ctx,
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
gum_function_context_remove_listener (GumFunctionContext * function_ctx,
                                      GumInvocationListener * listener)
{
  ListenerEntry * entry;
  guint i;

  entry = gum_function_context_find_listener_entry (function_ctx, listener);
  g_assert (entry != NULL);

  for (i = 0; i != function_ctx->listener_entries->len; i++)
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
gum_function_context_has_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener)
{
  return gum_function_context_find_listener_entry (function_ctx,
      listener) != NULL;
}

static ListenerEntry *
gum_function_context_find_listener_entry (GumFunctionContext * function_ctx,
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

gpointer
_gum_interceptor_thread_get_side_stack (gpointer original_stack)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;
  gint page_size = gum_query_page_size ();
  gpointer aligned_original_stack;
  gpointer aligned_side_stack;

  interceptor_ctx = get_interceptor_thread_context ();

  if (interceptor_ctx->thread_side_stack < original_stack &&
      original_stack < interceptor_ctx->thread_side_stack +
          GUM_THREAD_SIDE_STACK_SIZE)
    return original_stack;

  aligned_side_stack = interceptor_ctx->thread_side_stack +
      GUM_THREAD_SIDE_STACK_SIZE - page_size;

  aligned_original_stack =
     GSIZE_TO_POINTER(GPOINTER_TO_SIZE(original_stack) -
         (GPOINTER_TO_SIZE(original_stack) % page_size));

  memcpy (aligned_side_stack, aligned_original_stack, page_size);

  entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  /* we need to pop the saved cpu context from the original_stack in order
   * to get to the REAL original stack of the target function */
  entry->saved_original_stack = original_stack + (9 * 4) + 8;

  return aligned_side_stack + (original_stack - aligned_original_stack);
}

gpointer
_gum_interceptor_thread_get_orig_stack (gpointer current_stack)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();

  if (interceptor_ctx->stack->len != 1)
    return current_stack;

  if (current_stack > interceptor_ctx->thread_side_stack &&
      current_stack < interceptor_ctx->thread_side_stack +
          GUM_THREAD_SIDE_STACK_SIZE)
  {
    entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
    memcpy (entry->saved_original_stack - 8, current_stack, 8);
    return entry->saved_original_stack - 8;
  }
  else
    return current_stack;
}
#endif

void
_gum_function_context_begin_invocation (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context,
                                        gpointer * caller_ret_addr,
                                        gpointer * next_hop)
{
  GumInterceptor * interceptor = function_ctx->interceptor;
  GumInterceptorPrivate * priv = interceptor->priv;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStack * stack;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx = NULL;
  gint system_error;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave;

#ifdef G_OS_WIN32
  system_error = GetLastError ();
#endif

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  stack_entry = gum_invocation_stack_peek_top (stack);
  if (stack_entry != NULL && stack_entry->calling_replacement &&
      stack_entry->invocation_context.function ==
      function_ctx->function_address)
  {
    *next_hop = function_ctx->on_invoke_trampoline;
    return;
  }

  if (GUM_TLS_KEY_GET_VALUE (_gum_interceptor_guard_key) == interceptor)
  {
    *next_hop = function_ctx->on_invoke_trampoline;
    return;
  }
  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, interceptor);

#ifndef G_OS_WIN32
  system_error = errno;
#endif

  if (priv->selected_thread_id != 0)
  {
    invoke_listeners =
        gum_process_get_current_thread_id () == priv->selected_thread_id;
  }

  if (invoke_listeners)
  {
    invoke_listeners = (interceptor_ctx->ignore_level == 0);
  }

  will_trap_on_leave =
      function_ctx->replacement_function != NULL || invoke_listeners;
  if (will_trap_on_leave)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        *caller_ret_addr);
    invocation_ctx = &stack_entry->invocation_context;

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
  }

  if (invoke_listeners)
  {
    guint i;

    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->system_error = system_error;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    for (i = 0; i < function_ctx->listener_entries->len; i++)
    {
      ListenerEntry * listener_entry;
      ListenerInvocationState state;

      listener_entry =
          gum_array_index (function_ctx->listener_entries, ListenerEntry *, i);

      state.point_cut = GUM_POINT_ENTER;
      state.entry = listener_entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

#ifdef HAVE_QNX
      gpointer stack_address = &stack_address;
      if (stack_address > interceptor_ctx->thread_side_stack &&
          stack_address < interceptor_ctx->thread_side_stack +
              GUM_THREAD_SIDE_STACK_SIZE)
      {
        /* we're already on the side stack, no need to switch. */
        listener_entry->listener_interface->on_enter (
            listener_entry->listener_instance, invocation_ctx);
      }
      else
      {
        gum_exec_callback_func_with_side_stack (
            listener_entry->listener_instance, invocation_ctx,
            listener_entry->listener_interface->on_enter,
            interceptor_ctx->thread_side_stack +
            GUM_THREAD_SIDE_STACK_SIZE - 4);
      }
#else
      listener_entry->listener_interface->on_enter (
          listener_entry->listener_instance, invocation_ctx);
#endif
    }

    system_error = invocation_ctx->system_error;
  }

#ifdef G_OS_WIN32
  SetLastError (system_error);
#else
  errno = system_error;
#endif

  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, NULL);

  if (will_trap_on_leave)
  {
    *caller_ret_addr = function_ctx->on_leave_trampoline;
    g_atomic_int_inc (function_ctx->trampoline_usage_counter);
  }

  if (function_ctx->replacement_function != NULL)
  {
    stack_entry->calling_replacement = TRUE;
    stack_entry->cpu_context = *cpu_context;
    invocation_ctx->cpu_context = &stack_entry->cpu_context;
    invocation_ctx->backend = &interceptor_ctx->replacement_backend;
    invocation_ctx->backend->data = function_ctx->replacement_function_data;

    *next_hop = function_ctx->replacement_function;
  }
  else
  {
    *next_hop = function_ctx->on_invoke_trampoline;
  }
}

void
_gum_function_context_end_invocation (GumFunctionContext * function_ctx,
                                      GumCpuContext * cpu_context,
                                      gpointer * next_hop)
{
  gint system_error;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * stack_entry;
  gpointer caller_ret_addr;
  GumInvocationContext * invocation_ctx;
  guint i;

#ifdef G_OS_WIN32
  system_error = GetLastError ();
#endif

  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, function_ctx->interceptor);

#ifndef G_OS_WIN32
  system_error = errno;
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  caller_ret_addr = stack_entry->caller_ret_addr;
  *next_hop = caller_ret_addr;
  g_atomic_int_dec_and_test (function_ctx->trampoline_usage_counter);

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  invocation_ctx->system_error = system_error;
  invocation_ctx->backend = &interceptor_ctx->listener_backend;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = (guint32) caller_ret_addr;
# else
  cpu_context->rip = (guint64) caller_ret_addr;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = (guint32) caller_ret_addr;
#elif defined (HAVE_ARM64)
  cpu_context->pc = (guint64) caller_ret_addr;
#else
# error Unsupported architecture
#endif

  for (i = 0; i < function_ctx->listener_entries->len; i++)
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
    gpointer stack_address = &stack_address;
    if (stack_address > interceptor_ctx->thread_side_stack &&
        stack_address < interceptor_ctx->thread_side_stack +
            GUM_THREAD_SIDE_STACK_SIZE)
    {
      /* we're already on the side stack, no need to switch. */
      entry->listener_interface->on_leave (entry->listener_instance,
          invocation_ctx);
    }
    else
    {
      gum_exec_callback_func_with_side_stack (entry->listener_instance,
          invocation_ctx, entry->listener_interface->on_leave,
          interceptor_ctx->thread_side_stack + GUM_THREAD_SIDE_STACK_SIZE - 4);
    }
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

  GUM_TLS_KEY_SET_VALUE (_gum_interceptor_guard_key, NULL);
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
                           GumFunctionContext * function_ctx,
                           gpointer caller_ret_addr)
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

static gpointer
gum_interceptor_resolve (GumInterceptor * self,
                         gpointer address)
{
  if (!gum_interceptor_has (self, address))
  {
    gpointer target;

    target = _gum_interceptor_backend_resolve_redirect (self->priv->backend,
        address);
    if (target != NULL)
      return gum_interceptor_resolve (self, target);
  }

  return address;
}

static gboolean
gum_interceptor_has (GumInterceptor * self,
                     gpointer function_address)
{
  return gum_hash_table_lookup (self->priv->function_by_address,
      function_address) != NULL;
}

static void
gum_function_context_wait_for_idle_trampoline (GumFunctionContext * ctx)
{
  if (ctx->trampoline_usage_counter == NULL)
    return;

  while (*ctx->trampoline_usage_counter != 0)
    g_thread_yield ();
  g_thread_yield ();
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
