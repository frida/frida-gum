/*
 * Copyright (C) 2008-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "guminterceptor-priv.h"

#include "gumcodesegment.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess.h"
#include "gumtls.h"

#include <string.h>

#ifdef HAVE_MIPS
#define GUM_INTERCEPTOR_CODE_SLICE_SIZE 1024
#else
#define GUM_INTERCEPTOR_CODE_SLICE_SIZE 256
#endif

G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT);

#define GUM_INTERCEPTOR_LOCK()   (g_rec_mutex_lock (&priv->mutex))
#define GUM_INTERCEPTOR_UNLOCK() (g_rec_mutex_unlock (&priv->mutex))

typedef struct _GumInterceptorTransaction GumInterceptorTransaction;
typedef struct _GumDestroyTask GumDestroyTask;
typedef struct _GumPrologueWrite GumPrologueWrite;
typedef struct _ListenerEntry ListenerEntry;
typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _GumInvocationStackEntry GumInvocationStackEntry;
typedef struct _ListenerDataSlot ListenerDataSlot;
typedef struct _ListenerInvocationState ListenerInvocationState;

typedef void (* GumPrologueWriteFunc) (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

struct _GumInterceptorTransaction
{
  gboolean is_dirty;
  gint level;
  GQueue * pending_destroy_tasks;
  GHashTable * pending_prologue_writes;

  GumInterceptor * interceptor;
};

struct _GumInterceptorPrivate
{
  GRecMutex mutex;

  GHashTable * function_by_address;

  GumInterceptorBackend * backend;
  GumCodeAllocator allocator;

  volatile guint selected_thread_id;

  GumInterceptorTransaction current_transaction;
};

struct _GumDestroyTask
{
  GumFunctionContext * ctx;
  GDestroyNotify notify;
  gpointer data;
};

struct _GumPrologueWrite
{
  GumFunctionContext * ctx;
  GumPrologueWriteFunc func;
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

  GArray * listener_data_slots;
};

struct _GumInvocationStackEntry
{
  gpointer trampoline_ret_addr;
  gpointer caller_ret_addr;
  GumInvocationContext invocation_context;
  GumCpuContext cpu_context;
  guint8 listener_invocation_data[GUM_MAX_LISTENERS_PER_FUNCTION]
      [GUM_MAX_LISTENER_DATA];
  gboolean calling_replacement;
  gint original_system_error;
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
static void gum_interceptor_activate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);
static void gum_interceptor_deactivate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

static void gum_interceptor_transaction_init (
    GumInterceptorTransaction * transaction, GumInterceptor * interceptor);
static void gum_interceptor_transaction_destroy (
    GumInterceptorTransaction * transaction);
static void gum_interceptor_transaction_begin (
    GumInterceptorTransaction * self);
static void gum_interceptor_transaction_end (GumInterceptorTransaction * self);
static void gum_interceptor_transaction_schedule_destroy (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GDestroyNotify notify, gpointer data);
static void gum_interceptor_transaction_schedule_prologue_write (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GumPrologueWriteFunc func);

static GumFunctionContext * gum_function_context_new (
    GumInterceptor * interceptor, gpointer function_address);
static void gum_function_context_finalize (GumFunctionContext * function_ctx);
static void gum_function_context_destroy (GumFunctionContext * function_ctx);
static void gum_function_context_perform_destroy (
    GumFunctionContext * function_ctx);
static gboolean gum_function_context_is_empty (
    GumFunctionContext * function_ctx);
static void gum_function_context_add_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener,
    gpointer function_data);
static void gum_function_context_remove_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static void listener_entry_free (ListenerEntry * entry);
static gboolean gum_function_context_has_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx);

static InterceptorThreadContext * get_interceptor_thread_context (void);
static void release_interceptor_thread_context (
    InterceptorThreadContext * context);
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

static gpointer gum_page_address_from_pointer (gpointer ptr);
static gint gum_page_address_compare (gconstpointer a, gconstpointer b);

static GMutex _gum_interceptor_lock;
static GumInterceptor * _the_interceptor = NULL;

static GumSpinlock gum_interceptor_thread_context_lock;
static GHashTable * gum_interceptor_thread_contexts;
static GPrivate gum_interceptor_context_private =
    G_PRIVATE_INIT ((GDestroyNotify) release_interceptor_thread_context);
static GumTlsKey gum_interceptor_guard_key;

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
  gum_spinlock_init (&gum_interceptor_thread_context_lock);
  gum_interceptor_thread_contexts = g_hash_table_new_full (NULL, NULL,
      (GDestroyNotify) interceptor_thread_context_destroy, NULL);

  gum_interceptor_guard_key = gum_tls_key_new ();
}

void
_gum_interceptor_deinit (void)
{
  gum_tls_key_free (gum_interceptor_guard_key);

  g_hash_table_unref (gum_interceptor_thread_contexts);
  gum_interceptor_thread_contexts = NULL;

  gum_spinlock_free (&gum_interceptor_thread_context_lock);
}

static void
gum_interceptor_init (GumInterceptor * self)
{
  GumInterceptorPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_INTERCEPTOR,
      GumInterceptorPrivate);

  g_rec_mutex_init (&priv->mutex);

  priv->function_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_function_context_destroy);

  gum_code_allocator_init (&priv->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE);
  priv->backend = _gum_interceptor_backend_create (&priv->allocator);

  gum_interceptor_transaction_init (&priv->current_transaction, self);
}

static void
gum_interceptor_dispose (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = self->priv;

  GUM_INTERCEPTOR_LOCK ();
  gum_interceptor_transaction_begin (&priv->current_transaction);
  priv->current_transaction.is_dirty = TRUE;

  g_hash_table_remove_all (priv->function_by_address);

  gum_interceptor_transaction_end (&priv->current_transaction);
  GUM_INTERCEPTOR_UNLOCK ();

  G_OBJECT_CLASS (gum_interceptor_parent_class)->dispose (object);
}

static void
gum_interceptor_finalize (GObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);
  GumInterceptorPrivate * priv = self->priv;

  gum_interceptor_transaction_destroy (&priv->current_transaction);

  _gum_interceptor_backend_destroy (priv->backend);

  g_rec_mutex_clear (&priv->mutex);

  g_hash_table_unref (priv->function_by_address);

  gum_code_allocator_free (&priv->allocator);

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_mutex_lock (&_gum_interceptor_lock);

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

  g_mutex_unlock (&_gum_interceptor_lock);

  return interceptor;
}

static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  (void) data;

  g_mutex_lock (&_gum_interceptor_lock);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_mutex_unlock (&_gum_interceptor_lock);
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
  gum_interceptor_transaction_begin (&priv->current_transaction);
  priv->current_transaction.is_dirty = TRUE;

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
    gum_interceptor_transaction_end (&priv->current_transaction);
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
  GHashTableIter iter;
  GumFunctionContext * function_ctx;
  InterceptorThreadContext * thread_ctx;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK ();
  gum_interceptor_transaction_begin (&priv->current_transaction);
  priv->current_transaction.is_dirty = TRUE;

  g_hash_table_iter_init (&iter, priv->function_by_address);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &function_ctx))
  {
    if (gum_function_context_has_listener (function_ctx, listener))
    {
      gum_function_context_remove_listener (function_ctx, listener);

      gum_interceptor_transaction_schedule_destroy (&priv->current_transaction,
          function_ctx, g_object_unref, g_object_ref (listener));

      if (gum_function_context_is_empty (function_ctx))
      {
        g_hash_table_iter_remove (&iter);
      }
    }
  }

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_iter_init (&iter, gum_interceptor_thread_contexts);
  while (g_hash_table_iter_next (&iter, (gpointer *) &thread_ctx, NULL))
    interceptor_thread_context_forget_listener_data (thread_ctx, listener);
  gum_spinlock_release (&gum_interceptor_thread_context_lock);

  gum_interceptor_transaction_end (&priv->current_transaction);
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
  gum_interceptor_transaction_begin (&priv->current_transaction);
  priv->current_transaction.is_dirty = TRUE;

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
    gum_interceptor_transaction_end (&priv->current_transaction);
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
  gum_interceptor_transaction_begin (&priv->current_transaction);
  priv->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = (GumFunctionContext *) g_hash_table_lookup (
      priv->function_by_address, function_address);
  if (function_ctx == NULL)
    goto beach;

  function_ctx->replacement_function = NULL;
  function_ctx->replacement_function_data = NULL;

  if (gum_function_context_is_empty (function_ctx))
  {
    g_hash_table_remove (priv->function_by_address, function_address);
  }

beach:
  gum_interceptor_transaction_end (&priv->current_transaction);
  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_begin_transaction (GumInterceptor * self)
{
  GumInterceptorPrivate * priv = self->priv;

  GUM_INTERCEPTOR_LOCK ();
  gum_interceptor_transaction_begin (&priv->current_transaction);
  GUM_INTERCEPTOR_UNLOCK ();
}

void
gum_interceptor_end_transaction (GumInterceptor * self)
{
  GumInterceptorPrivate * priv = self->priv;

  GUM_INTERCEPTOR_LOCK ();
  gum_interceptor_transaction_end (&priv->current_transaction);
  GUM_INTERCEPTOR_UNLOCK ();
}

gboolean
gum_interceptor_flush (GumInterceptor * self)
{
  GumInterceptorPrivate * priv = self->priv;
  gboolean flushed = FALSE;

  GUM_INTERCEPTOR_LOCK ();

  if (priv->current_transaction.level == 0)
  {
    gum_interceptor_transaction_begin (&priv->current_transaction);
    gum_interceptor_transaction_end (&priv->current_transaction);

    flushed =
        g_queue_is_empty (priv->current_transaction.pending_destroy_tasks);
  }

  GUM_INTERCEPTOR_UNLOCK ();

  return flushed;
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

  context = g_private_get (&gum_interceptor_context_private);
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
        &g_array_index (self, GumInvocationStackEntry, i);
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

  ctx = (GumFunctionContext *) g_hash_table_lookup (priv->function_by_address,
      function_address);
  if (ctx != NULL)
    return ctx;

  ctx = gum_function_context_new (self, function_address);
  if (ctx == NULL)
    return NULL;

  if (!_gum_interceptor_backend_create_trampoline (priv->backend, ctx))
  {
    gum_function_context_finalize (ctx);
    return NULL;
  }

  g_hash_table_insert (priv->function_by_address, function_address, ctx);

  gum_interceptor_transaction_schedule_prologue_write (
      &priv->current_transaction, ctx, gum_interceptor_activate);

  return ctx;
}

static void
gum_interceptor_activate (GumInterceptor * self,
                          GumFunctionContext * ctx,
                          gpointer prologue)
{
  if (ctx->destroyed)
    return;

  g_assert (!ctx->activated);
  ctx->activated = TRUE;

  _gum_interceptor_backend_activate_trampoline (self->priv->backend, ctx,
      prologue);
}

static void
gum_interceptor_deactivate (GumInterceptor * self,
                            GumFunctionContext * ctx,
                            gpointer prologue)
{
  GumInterceptorBackend * backend = self->priv->backend;

  g_assert (ctx->activated);
  ctx->activated = FALSE;

  _gum_interceptor_backend_deactivate_trampoline (backend, ctx, prologue);
}

static void
gum_interceptor_transaction_init (GumInterceptorTransaction * transaction,
                                  GumInterceptor * interceptor)
{
  transaction->is_dirty = FALSE;
  transaction->level = 0;
  transaction->pending_destroy_tasks = g_queue_new ();
  transaction->pending_prologue_writes = g_hash_table_new_full (
      NULL, NULL, NULL, (GDestroyNotify) g_array_unref);

  transaction->interceptor = interceptor;
}

static void
gum_interceptor_transaction_destroy (GumInterceptorTransaction * transaction)
{
  GumDestroyTask * task;

  g_hash_table_unref (transaction->pending_prologue_writes);

  while ((task = g_queue_pop_head (transaction->pending_destroy_tasks)) != NULL)
  {
    task->notify (task->data);

    g_slice_free (GumDestroyTask, task);
  }
  g_queue_free (transaction->pending_destroy_tasks);
}

static void
gum_interceptor_transaction_begin (GumInterceptorTransaction * self)
{
  self->level++;
}

static void
gum_interceptor_transaction_end (GumInterceptorTransaction * self)
{
  GumInterceptor * interceptor = self->interceptor;
  GumInterceptorPrivate * priv = self->interceptor->priv;
  GumInterceptorTransaction transaction_copy;
  GList * addresses, * cur;
  guint page_size;
  gboolean rwx_supported, code_segment_supported;
  GumDestroyTask * task;

  self->level--;
  if (self->level > 0)
    return;

  if (!self->is_dirty)
    return;

  gum_interceptor_ignore_current_thread (interceptor);

  gum_code_allocator_commit (&priv->allocator);

  if (g_queue_is_empty (self->pending_destroy_tasks) &&
      g_hash_table_size (self->pending_prologue_writes) == 0)
  {
    priv->current_transaction.is_dirty = FALSE;
    goto no_changes;
  }

  transaction_copy = priv->current_transaction;
  self = &transaction_copy;
  gum_interceptor_transaction_init (&priv->current_transaction, interceptor);

  addresses = g_hash_table_get_keys (self->pending_prologue_writes);
  addresses = g_list_sort (addresses, gum_page_address_compare);

  page_size = gum_query_page_size ();

  rwx_supported = gum_query_is_rwx_supported ();
  code_segment_supported = gum_code_segment_is_supported ();

  if (rwx_supported || !code_segment_supported)
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;

      gum_mprotect (target_page, page_size, protection);
    }

    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;
      GArray * pending;
      guint i;

      pending = g_hash_table_lookup (self->pending_prologue_writes,
          target_page);
      g_assert (pending != NULL);

      for (i = 0; i != pending->len; i++)
      {
        GumPrologueWrite * write;

        write = &g_array_index (pending, GumPrologueWrite, i);

        write->func (interceptor, write->ctx,
            _gum_interceptor_backend_get_function_address (write->ctx));
      }
    }

    if (!rwx_supported)
    {
      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_mprotect (target_page, page_size, GUM_PAGE_RX);
      }
    }

    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;

      gum_clear_cache (target_page, page_size);
    }
  }
  else
  {
    guint num_pages;
    GumCodeSegment * segment;
    guint8 * source_page;
    gsize source_offset;

    num_pages = g_hash_table_size (self->pending_prologue_writes);
    segment = gum_code_segment_new (num_pages * page_size, NULL);

    source_page = gum_code_segment_get_address (segment);
    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      guint8 * target_page = cur->data;
      GArray * pending;
      guint i;

      pending = g_hash_table_lookup (self->pending_prologue_writes,
          target_page);
      g_assert (pending != NULL);

      memcpy (source_page, target_page, page_size);

      for (i = 0; i != pending->len; i++)
      {
        GumPrologueWrite * write;

        write = &g_array_index (pending, GumPrologueWrite, i);

        write->func (interceptor, write->ctx, source_page +
            ((guint8 *) _gum_interceptor_backend_get_function_address (
                write->ctx) - target_page));
      }

      source_page += page_size;
    }

    gum_code_segment_realize (segment);

    source_offset = 0;
    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;

      gum_code_segment_map (segment, source_offset, page_size, target_page);

      gum_clear_cache (target_page, page_size);

      source_offset += page_size;
    }

    gum_code_segment_free (segment);
  }

  g_list_free (addresses);

  while ((task = g_queue_pop_head (self->pending_destroy_tasks)) != NULL)
  {
    if (task->ctx->trampoline_usage_counter == 0)
    {
      GUM_INTERCEPTOR_UNLOCK ();
      task->notify (task->data);
      GUM_INTERCEPTOR_LOCK ();

      g_slice_free (GumDestroyTask, task);
    }
    else
    {
      priv->current_transaction.is_dirty = TRUE;
      g_queue_push_tail (priv->current_transaction.pending_destroy_tasks, task);
    }
  }

  gum_interceptor_transaction_destroy (self);

no_changes:
  gum_interceptor_unignore_current_thread (interceptor);
}

static void
gum_interceptor_transaction_schedule_destroy (GumInterceptorTransaction * self,
                                              GumFunctionContext * ctx,
                                              GDestroyNotify notify,
                                              gpointer data)
{
  GumDestroyTask * task;

  task = g_slice_new (GumDestroyTask);
  task->ctx = ctx;
  task->notify = notify;
  task->data = data;

  g_queue_push_tail (self->pending_destroy_tasks, task);
}

static void
gum_interceptor_transaction_schedule_prologue_write (
    GumInterceptorTransaction * self,
    GumFunctionContext * ctx,
    GumPrologueWriteFunc func)
{
  guint8 * function_address;
  gpointer start_page, end_page;
  GArray * pending;
  GumPrologueWrite write;

  function_address = _gum_interceptor_backend_get_function_address (ctx);

  start_page = gum_page_address_from_pointer (function_address);
  end_page = gum_page_address_from_pointer (function_address +
      ctx->overwritten_prologue_len - 1);

  pending = g_hash_table_lookup (self->pending_prologue_writes, start_page);
  if (pending == NULL)
  {
    pending = g_array_new (FALSE, FALSE, sizeof (GumPrologueWrite));
    g_hash_table_insert (self->pending_prologue_writes, start_page, pending);
  }

  write.ctx = ctx;
  write.func = func;
  g_array_append_val (pending, write);

  if (end_page != start_page)
  {
    pending = g_hash_table_lookup (self->pending_prologue_writes, end_page);
    if (pending == NULL)
    {
      pending = g_array_new (FALSE, FALSE, sizeof (GumPrologueWrite));
      g_hash_table_insert (self->pending_prologue_writes, end_page, pending);
    }
  }
}

static GumFunctionContext *
gum_function_context_new (GumInterceptor * interceptor,
                          gpointer function_address)
{
  GumFunctionContext * ctx;

  ctx = g_slice_new0 (GumFunctionContext);
  ctx->function_address = function_address;

  ctx->listener_entries =
      g_ptr_array_new_full (1, (GDestroyNotify) listener_entry_free);

  ctx->interceptor = interceptor;

  return ctx;
}

static void
gum_function_context_finalize (GumFunctionContext * function_ctx)
{
  g_assert (function_ctx->trampoline_slice == NULL);

  g_ptr_array_unref (g_atomic_pointer_get (&function_ctx->listener_entries));

  g_slice_free (GumFunctionContext, function_ctx);
}

static void
gum_function_context_destroy (GumFunctionContext * function_ctx)
{
  GumInterceptorTransaction * transaction =
      &function_ctx->interceptor->priv->current_transaction;

  g_assert (!function_ctx->destroyed);
  function_ctx->destroyed = TRUE;

  if (function_ctx->activated)
  {
    gum_interceptor_transaction_schedule_prologue_write (transaction,
        function_ctx, gum_interceptor_deactivate);
  }

  gum_interceptor_transaction_schedule_destroy (transaction, function_ctx,
      (GDestroyNotify) gum_function_context_perform_destroy, function_ctx);
}

static void
gum_function_context_perform_destroy (GumFunctionContext * function_ctx)
{
  _gum_interceptor_backend_destroy_trampoline (
      function_ctx->interceptor->priv->backend, function_ctx);

  gum_function_context_finalize (function_ctx);
}

static gboolean
gum_function_context_is_empty (GumFunctionContext * function_ctx)
{
  if (function_ctx->replacement_function != NULL)
    return FALSE;

  return gum_function_context_find_taken_listener_slot (function_ctx) == NULL;
}

static void
gum_function_context_add_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener,
                                   gpointer function_data)
{
  ListenerEntry * entry;
  GPtrArray * old_entries, * new_entries;
  guint i;

  entry = g_slice_new (ListenerEntry);
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_INTERFACE (listener);
  entry->listener_instance = listener;
  entry->function_data = function_data;

  old_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
  new_entries = g_ptr_array_new_full (old_entries->len + 1,
      (GDestroyNotify) listener_entry_free);
  for (i = 0; i != old_entries->len; i++)
  {
    ListenerEntry * old_entry = g_ptr_array_index (old_entries, i);
    if (old_entry != NULL)
      g_ptr_array_add (new_entries, g_slice_dup (ListenerEntry, old_entry));
  }
  g_ptr_array_add (new_entries, entry);

  g_atomic_pointer_set (&function_ctx->listener_entries, new_entries);
  gum_interceptor_transaction_schedule_destroy (
      &function_ctx->interceptor->priv->current_transaction, function_ctx,
      (GDestroyNotify) g_ptr_array_unref, old_entries);

  if (entry->listener_interface->on_leave != NULL)
  {
    function_ctx->has_on_leave_listener = TRUE;
  }
}

static void
listener_entry_free (ListenerEntry * entry)
{
  g_slice_free (ListenerEntry, entry);
}

static void
gum_function_context_remove_listener (GumFunctionContext * function_ctx,
                                      GumInvocationListener * listener)
{
  ListenerEntry ** slot;
  gboolean has_on_leave_listener;
  GPtrArray * listener_entries;
  guint i;

  slot = gum_function_context_find_listener (function_ctx, listener);
  g_assert (slot != NULL);
  listener_entry_free (*slot);
  *slot = NULL;

  has_on_leave_listener = FALSE;
  listener_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * entry = g_ptr_array_index (listener_entries, i);
    if (entry != NULL && entry->listener_interface->on_leave != NULL)
    {
      has_on_leave_listener = TRUE;
      break;
    }
  }
  function_ctx->has_on_leave_listener = has_on_leave_listener;
}

static gboolean
gum_function_context_has_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener)
{
  return gum_function_context_find_listener (function_ctx, listener) != NULL;
}

static ListenerEntry **
gum_function_context_find_listener (GumFunctionContext * function_ctx,
                                    GumInvocationListener * listener)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL && (*slot)->listener_instance == listener)
      return slot;
  }

  return NULL;
}

static ListenerEntry **
gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL)
      return slot;
  }

  return NULL;
}

void
_gum_function_context_begin_invocation (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context,
                                        gpointer * caller_ret_addr,
                                        gpointer * next_hop)
{
  GumInterceptor * interceptor;
  GumInterceptorPrivate * priv;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStack * stack;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx = NULL;
  gint system_error;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave;
  gsize pc;

  g_atomic_int_inc (&function_ctx->trampoline_usage_counter);

  interceptor = function_ctx->interceptor;
  priv = interceptor->priv;

#ifdef G_OS_WIN32
  system_error = gum_thread_get_system_error ();
#endif

  if (gum_tls_key_get_value (gum_interceptor_guard_key) == interceptor)
  {
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }
  gum_tls_key_set_value (gum_interceptor_guard_key, interceptor);

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  stack_entry = gum_invocation_stack_peek_top (stack);
  if (stack_entry != NULL && stack_entry->calling_replacement &&
      stack_entry->invocation_context.function ==
      function_ctx->function_address)
  {
    gum_tls_key_set_value (gum_interceptor_guard_key, NULL);
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }

#ifndef G_OS_WIN32
  system_error = gum_thread_get_system_error ();
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

  will_trap_on_leave = function_ctx->replacement_function != NULL ||
      (invoke_listeners && function_ctx->has_on_leave_listener);
  if (will_trap_on_leave)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        *caller_ret_addr);
    invocation_ctx = &stack_entry->invocation_context;
  }
  else if (invoke_listeners)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        function_ctx->function_address);
    invocation_ctx = &stack_entry->invocation_context;
  }

  if (invocation_ctx != NULL)
    invocation_ctx->system_error = system_error;

  pc = GPOINTER_TO_SIZE (*caller_ret_addr);

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = pc;
# else
  cpu_context->rip = pc;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = pc;
#elif defined (HAVE_ARM64)
  cpu_context->pc = pc;
#elif defined (HAVE_MIPS)
  cpu_context->pc = pc;
#else
# error Unsupported architecture
#endif

  if (invoke_listeners)
  {
    GPtrArray * listener_entries;
    guint i;

    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    listener_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
    for (i = 0; i != listener_entries->len; i++)
    {
      ListenerEntry * listener_entry;
      ListenerInvocationState state;

      listener_entry = g_ptr_array_index (listener_entries, i);
      if (listener_entry == NULL)
        continue;

      state.point_cut = GUM_POINT_ENTER;
      state.entry = listener_entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

      if (listener_entry->listener_interface->on_enter != NULL)
      {
        listener_entry->listener_interface->on_enter (
            listener_entry->listener_instance, invocation_ctx);
      }
    }

    system_error = invocation_ctx->system_error;
  }

  if (!will_trap_on_leave && invoke_listeners)
  {
    gum_invocation_stack_pop (interceptor_ctx->stack);
  }

  gum_thread_set_system_error (system_error);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  if (will_trap_on_leave)
  {
    *caller_ret_addr = function_ctx->on_leave_trampoline;
  }

  if (function_ctx->replacement_function != NULL)
  {
    stack_entry->calling_replacement = TRUE;
    stack_entry->cpu_context = *cpu_context;
    stack_entry->original_system_error = system_error;
    invocation_ctx->cpu_context = &stack_entry->cpu_context;
    invocation_ctx->backend = &interceptor_ctx->replacement_backend;
    invocation_ctx->backend->data = function_ctx->replacement_function_data;

    *next_hop = function_ctx->replacement_function;
  }
  else
  {
    *next_hop = function_ctx->on_invoke_trampoline;
  }

  if (!will_trap_on_leave)
  {
    g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
  }

  return;

bypass:
  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
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
  GPtrArray * listener_entries;
  guint i;

#ifdef G_OS_WIN32
  system_error = gum_thread_get_system_error ();
#endif

  gum_tls_key_set_value (gum_interceptor_guard_key, function_ctx->interceptor);

#ifndef G_OS_WIN32
  system_error = gum_thread_get_system_error ();
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  caller_ret_addr = stack_entry->caller_ret_addr;
  *next_hop = caller_ret_addr;

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  if (stack_entry->calling_replacement &&
      invocation_ctx->system_error != stack_entry->original_system_error)
  {
    system_error = invocation_ctx->system_error;
  }
  else
  {
    invocation_ctx->system_error = system_error;
  }
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
#elif defined (HAVE_MIPS)
  cpu_context->pc = (guint32) caller_ret_addr;
#else
# error Unsupported architecture
#endif

  listener_entries = g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * listener_entry;
    ListenerInvocationState state;

    listener_entry = g_ptr_array_index (listener_entries, i);
    if (listener_entry == NULL)
      continue;

    state.point_cut = GUM_POINT_LEAVE;
    state.entry = listener_entry;
    state.interceptor_ctx = interceptor_ctx;
    state.invocation_data = stack_entry->listener_invocation_data[i];
    invocation_ctx->backend->data = &state;

    if (listener_entry->listener_interface->on_leave != NULL)
    {
      listener_entry->listener_interface->on_leave (
          listener_entry->listener_instance, invocation_ctx);
    }
  }

  gum_thread_set_system_error (invocation_ctx->system_error);

  gum_invocation_stack_pop (interceptor_ctx->stack);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}

static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = g_private_get (&gum_interceptor_context_private);
  if (context == NULL)
  {
    context = interceptor_thread_context_new ();

    gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
    g_hash_table_add (gum_interceptor_thread_contexts, context);
    gum_spinlock_release (&gum_interceptor_thread_context_lock);

    g_private_set (&gum_interceptor_context_private, context);
  }

  return context;
}

static void
release_interceptor_thread_context (InterceptorThreadContext * context)
{
  if (gum_interceptor_thread_contexts == NULL)
    return;

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_remove (gum_interceptor_thread_contexts, context);
  gum_spinlock_release (&gum_interceptor_thread_context_lock);
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

static guint
gum_interceptor_invocation_get_depth (GumInvocationContext * context)
{
  InterceptorThreadContext * interceptor_ctx =
      (InterceptorThreadContext *) context->backend->state;

  return interceptor_ctx->stack->len - 1;
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
  gum_interceptor_invocation_get_depth,

  gum_interceptor_invocation_get_listener_thread_data,
  gum_interceptor_invocation_get_listener_function_data,
  gum_interceptor_invocation_get_listener_function_invocation_data,

  NULL,

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
  gum_interceptor_invocation_get_depth,

  NULL,
  NULL,
  NULL,

  gum_interceptor_invocation_get_replacement_function_data,

  NULL,
  NULL
};

static InterceptorThreadContext *
interceptor_thread_context_new (void)
{
  InterceptorThreadContext * context;

  context = g_slice_new0 (InterceptorThreadContext);

  gum_memcpy (&context->listener_backend,
      &gum_interceptor_listener_invocation_backend,
      sizeof (GumInvocationBackend));
  gum_memcpy (&context->replacement_backend,
      &gum_interceptor_replacement_invocation_backend,
      sizeof (GumInvocationBackend));
  context->listener_backend.state = context;
  context->replacement_backend.state = context;

  context->ignore_level = 0;

  context->stack = g_array_sized_new (FALSE, TRUE,
      sizeof (GumInvocationStackEntry), GUM_MAX_CALL_DEPTH);

  context->listener_data_slots = g_array_sized_new (FALSE, TRUE,
      sizeof (ListenerDataSlot), GUM_MAX_LISTENERS_PER_FUNCTION);

  return context;
}

static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  g_array_free (context->listener_data_slots, TRUE);

  g_array_free (context->stack, TRUE);

  g_slice_free (InterceptorThreadContext, context);
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

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
      return slot->data;
    else if (slot->owner == NULL)
      available_slot = slot;
  }

  if (available_slot == NULL)
  {
    g_array_set_size (self->listener_data_slots,
        self->listener_data_slots->len + 1);
    available_slot = &g_array_index (self->listener_data_slots,
        ListenerDataSlot, self->listener_data_slots->len - 1);
  }
  else
  {
    gum_memset (available_slot->data, 0, sizeof (available_slot->data));
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

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
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

  g_array_set_size (stack, stack->len + 1);
  entry = (GumInvocationStackEntry *)
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
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
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  caller_ret_addr = entry->caller_ret_addr;
  g_array_set_size (stack, stack->len - 1);

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
  return g_hash_table_lookup (self->priv->function_by_address,
      function_address) != NULL;
}

static gpointer
gum_page_address_from_pointer (gpointer ptr)
{
  return GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ptr) & ~((gsize) gum_query_page_size () - 1));
}

static gint
gum_page_address_compare (gconstpointer a,
                          gconstpointer b)
{
  return GPOINTER_TO_SIZE (a) - GPOINTER_TO_SIZE (b);
}
