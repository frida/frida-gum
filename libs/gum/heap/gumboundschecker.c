/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumboundschecker.h"

#include "guminterceptor.h"
#include "gummemory.h"
#include "gumpagepool.h"

#include <stdlib.h>
#include <string.h>
#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#else
# include <signal.h>
#endif

#define DEFAULT_POOL_SIZE       4096
#define DEFAULT_FRONT_ALIGNMENT   16

#define GUM_BOUNDS_CHECKER_LOCK()   (g_mutex_lock (self->priv->mutex))
#define GUM_BOUNDS_CHECKER_UNLOCK() (g_mutex_unlock (self->priv->mutex))

#define BLOCK_ALLOC_RETADDRS(b) \
    ((GumReturnAddressArray *) (b)->guard)
#define BLOCK_FREE_RETADDRS(b) \
    ((GumReturnAddressArray *) ((guint8 *) (b)->guard + ((b)->guard_size / 2)))

enum
{
  PROP_0,
  PROP_BACKTRACER,
  PROP_POOL_SIZE,
  PROP_FRONT_ALIGNMENT
};

struct _GumBoundsCheckerPrivate
{
  gboolean disposed;

  GMutex * mutex;

  GumBacktracerIface * backtracer_interface;
  GumBacktracer * backtracer_instance;
  GumBoundsOutputFunc output;
  gpointer output_user_data;

  GumInterceptor * interceptor;
  GumHeapApiList * heap_apis;
  gboolean attached;
  volatile gboolean detaching;

  guint pool_size;
  guint front_alignment;
  GumPagePool * page_pool;
};

#define GUM_BOUNDS_CHECKER_GET_PRIVATE(o) ((o)->priv)

static void gum_bounds_checker_dispose (GObject * object);
static void gum_bounds_checker_finalize (GObject * object);

static void gum_bounds_checker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_bounds_checker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gpointer replacement_malloc (gsize size);
static gpointer replacement_calloc (gsize num, gsize size);
static gpointer replacement_realloc (gpointer old_address,
    gsize new_size);
static void replacement_free (gpointer address);

static gpointer gum_bounds_checker_try_alloc (GumBoundsChecker * self,
    guint size, GumInvocationContext * ctx);
static gboolean gum_bounds_checker_try_free (GumBoundsChecker * self,
    gpointer address, GumInvocationContext * ctx);

static void gum_bounds_checker_append_backtrace (
    const GumReturnAddressArray * arr, GString * s);

#ifdef G_OS_WIN32
static gboolean gum_bounds_checker_on_exception (
    EXCEPTION_RECORD * exception_record, CONTEXT * context, gpointer user_data);
#else
static void gum_bounds_checker_on_invalid_access (int sig, siginfo_t * siginfo,
    void * context);
#endif

G_DEFINE_TYPE (GumBoundsChecker, gum_bounds_checker, G_TYPE_OBJECT);

G_LOCK_DEFINE_STATIC (gum_memaccess);
static guint gum_memaccess_refcount = 0;
#ifndef G_OS_WIN32
static struct sigaction gum_memaccess_old_sigsegv;
static struct sigaction gum_memaccess_old_sigbus;
#endif
static GSList * gum_memaccess_instances = NULL;

static void
gum_bounds_checker_class_init (GumBoundsCheckerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumBoundsCheckerPrivate));

  object_class->dispose = gum_bounds_checker_dispose;
  object_class->finalize = gum_bounds_checker_finalize;
  object_class->get_property = gum_bounds_checker_get_property;
  object_class->set_property = gum_bounds_checker_set_property;

  g_object_class_install_property (object_class, PROP_BACKTRACER,
      g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (object_class, PROP_POOL_SIZE,
      g_param_spec_uint ("pool-size", "Pool Size",
      "Pool size in number of pages",
      2, G_MAXUINT, DEFAULT_POOL_SIZE,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_FRONT_ALIGNMENT,
      g_param_spec_uint ("front-alignment", "Front Alignment",
      "Front alignment requirement",
      1, 64, DEFAULT_FRONT_ALIGNMENT,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gum_bounds_checker_init (GumBoundsChecker * self)
{
  GumBoundsCheckerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_BOUNDS_CHECKER,
      GumBoundsCheckerPrivate);

  priv = GUM_BOUNDS_CHECKER_GET_PRIVATE (self);

  priv->mutex = g_mutex_new ();

  priv->interceptor = gum_interceptor_obtain ();
  priv->pool_size = DEFAULT_POOL_SIZE;
  priv->front_alignment = DEFAULT_FRONT_ALIGNMENT;

  G_LOCK (gum_memaccess);
  if (gum_memaccess_refcount++ == 0)
  {
#ifndef G_OS_WIN32
    struct sigaction action;
    action.sa_sigaction = gum_bounds_checker_on_invalid_access;
    sigemptyset (&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    sigaction (SIGSEGV, &action, &gum_memaccess_old_sigsegv);
    sigaction (SIGBUS, &action, &gum_memaccess_old_sigbus);
#endif
  }
  gum_memaccess_instances =
      g_slist_prepend (gum_memaccess_instances, self);
  G_UNLOCK (gum_memaccess);

#ifdef G_OS_WIN32
  gum_win_exception_hook_add (gum_bounds_checker_on_exception, self);
#endif
}

static void
gum_bounds_checker_dispose (GObject * object)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);
  GumBoundsCheckerPrivate * priv = GUM_BOUNDS_CHECKER_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    gum_bounds_checker_detach (self);

#ifdef G_OS_WIN32
    gum_win_exception_hook_remove (gum_bounds_checker_on_exception);
#endif

    G_LOCK (gum_memaccess);
    if (--gum_memaccess_refcount == 0)
    {
#ifndef G_OS_WIN32
      sigaction (SIGSEGV, &gum_memaccess_old_sigsegv, NULL);
      memset (&gum_memaccess_old_sigsegv, 0,
          sizeof (gum_memaccess_old_sigsegv));
      sigaction (SIGBUS, &gum_memaccess_old_sigbus, NULL);
      memset (&gum_memaccess_old_sigbus, 0,
          sizeof (gum_memaccess_old_sigbus));
#endif
    }
    gum_memaccess_instances =
        g_slist_remove (gum_memaccess_instances, self);
    G_UNLOCK (gum_memaccess);

    g_object_unref (priv->interceptor);
    priv->interceptor = NULL;

    if (priv->backtracer_instance != NULL)
    {
      g_object_unref (priv->backtracer_instance);
      priv->backtracer_instance = NULL;
    }
    priv->backtracer_interface = NULL;
  }

  G_OBJECT_CLASS (gum_bounds_checker_parent_class)->dispose (object);
}

static void
gum_bounds_checker_finalize (GObject * object)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);

  g_mutex_free (self->priv->mutex);

  G_OBJECT_CLASS (gum_bounds_checker_parent_class)->finalize (object);
}

static void
gum_bounds_checker_get_property (GObject * object,
                                 guint property_id,
                                 GValue * value,
                                 GParamSpec * pspec)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);
  GumBoundsCheckerPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_BACKTRACER:
      g_value_set_object (value, priv->backtracer_instance);
      break;
    case PROP_POOL_SIZE:
      g_value_set_uint (value, gum_bounds_checker_get_pool_size (self));
      break;
    case PROP_FRONT_ALIGNMENT:
      g_value_set_uint (value, gum_bounds_checker_get_front_alignment (self));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_bounds_checker_set_property (GObject * object,
                                 guint property_id,
                                 const GValue * value,
                                 GParamSpec * pspec)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);
  GumBoundsCheckerPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_BACKTRACER:
      if (priv->backtracer_instance != NULL)
        g_object_unref (priv->backtracer_instance);
      priv->backtracer_instance = g_value_dup_object (value);

      if (priv->backtracer_instance != NULL)
      {
        priv->backtracer_interface =
            GUM_BACKTRACER_GET_INTERFACE (priv->backtracer_instance);
      }
      else
      {
        priv->backtracer_interface = NULL;
      }

      break;
    case PROP_POOL_SIZE:
      gum_bounds_checker_set_pool_size (self, g_value_get_uint (value));
      break;
    case PROP_FRONT_ALIGNMENT:
      gum_bounds_checker_set_front_alignment (self, g_value_get_uint (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumBoundsChecker *
gum_bounds_checker_new (GumBacktracer * backtracer,
                        GumBoundsOutputFunc func,
                        gpointer user_data)
{
  GumBoundsChecker * checker;
  GumBoundsCheckerPrivate * priv;

  checker = GUM_BOUNDS_CHECKER (g_object_new (GUM_TYPE_BOUNDS_CHECKER,
      "backtracer", backtracer,
      NULL));
  priv = checker->priv;

  priv->output = func;
  priv->output_user_data = user_data;

  return checker;
}

guint
gum_bounds_checker_get_pool_size (GumBoundsChecker * self)
{
  return self->priv->pool_size;
}

void
gum_bounds_checker_set_pool_size (GumBoundsChecker * self,
                                  guint pool_size)
{
  g_assert (self->priv->page_pool == NULL);
  self->priv->pool_size = pool_size;
}

guint
gum_bounds_checker_get_front_alignment (GumBoundsChecker * self)
{
  return self->priv->front_alignment;
}

void
gum_bounds_checker_set_front_alignment (GumBoundsChecker * self,
                                        guint pool_size)
{
  g_assert (self->priv->page_pool == NULL);
  self->priv->front_alignment = pool_size;
}

void
gum_bounds_checker_attach (GumBoundsChecker * self)
{
  GumHeapApiList * apis = gum_process_find_heap_apis ();
  gum_bounds_checker_attach_to_apis (self, apis);
  gum_heap_api_list_free (apis);
}

void
gum_bounds_checker_attach_to_apis (GumBoundsChecker * self,
                                   const GumHeapApiList * apis)
{
  GumBoundsCheckerPrivate * priv = GUM_BOUNDS_CHECKER_GET_PRIVATE (self);
  guint i;

  g_assert (priv->heap_apis == NULL);
  priv->heap_apis = gum_heap_api_list_copy (apis);

  g_assert (priv->page_pool == NULL);
  priv->page_pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE,
      priv->pool_size);
  g_object_set (priv->page_pool, "front-alignment", priv->front_alignment,
      NULL);

  for (i = 0; i != apis->len; i++)
  {
    const GumHeapApi * api = gum_heap_api_list_get_nth (apis, i);

#define GUM_REPLACE_API_FUNC(name) \
    gum_interceptor_replace_function (priv->interceptor, \
        GUM_FUNCPTR_TO_POINTER (api->name), \
        GUM_FUNCPTR_TO_POINTER (replacement_##name), self)

    GUM_REPLACE_API_FUNC (malloc);
    GUM_REPLACE_API_FUNC (calloc);
    GUM_REPLACE_API_FUNC (realloc);
    GUM_REPLACE_API_FUNC (free);

#undef GUM_REPLACE_API_FUNC
  }

  priv->attached = TRUE;
}

void
gum_bounds_checker_detach (GumBoundsChecker * self)
{
  GumBoundsCheckerPrivate * priv = GUM_BOUNDS_CHECKER_GET_PRIVATE (self);

  if (priv->attached)
  {
    guint i;

    priv->attached = FALSE;
    priv->detaching = TRUE;

    g_assert_cmpuint (gum_page_pool_peek_used (priv->page_pool), ==, 0);

    for (i = 0; i != priv->heap_apis->len; i++)
    {
      const GumHeapApi * api = gum_heap_api_list_get_nth (priv->heap_apis, i);

#define GUM_REVERT_API_FUNC(name) \
      gum_interceptor_revert_function (priv->interceptor, \
          GUM_FUNCPTR_TO_POINTER (api->name))

      GUM_REVERT_API_FUNC (malloc);
      GUM_REVERT_API_FUNC (calloc);
      GUM_REVERT_API_FUNC (realloc);
      GUM_REVERT_API_FUNC (free);

  #undef GUM_REVERT_API_FUNC
    }

    g_object_unref (priv->page_pool);
    priv->page_pool = NULL;

    gum_heap_api_list_free (priv->heap_apis);
    priv->heap_apis = NULL;
  }
}

static gpointer
replacement_malloc (gsize size)
{
  GumInvocationContext * ctx;
  GumBoundsChecker * self;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  self = GUM_RINCTX_GET_FUNC_DATA (ctx, GumBoundsChecker *);

  if (self->priv->detaching)
    goto fallback;

  GUM_BOUNDS_CHECKER_LOCK ();
  result = gum_bounds_checker_try_alloc (self, MAX (size, 1), ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();
  if (result == NULL)
    goto fallback;

  return result;

fallback:
  return malloc (size);
}

static gpointer
replacement_calloc (gsize num,
                    gsize size)
{
  GumInvocationContext * ctx;
  GumBoundsChecker * self;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  self = GUM_RINCTX_GET_FUNC_DATA (ctx, GumBoundsChecker *);

  if (self->priv->detaching)
    goto fallback;

  GUM_BOUNDS_CHECKER_LOCK ();
  result = gum_bounds_checker_try_alloc (self, MAX (num * size, 1), ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();
  if (result != NULL)
    memset (result, 0, num * size);
  else
    goto fallback;

  return result;

fallback:
  return calloc (num, size);
}

static gpointer
replacement_realloc (gpointer old_address,
                     gsize new_size)
{
  GumInvocationContext * ctx;
  GumBoundsChecker * self;
  gpointer result = NULL;
  GumBlockDetails old_block;
  gboolean success;

  ctx = gum_interceptor_get_current_invocation ();
  self = GUM_RINCTX_GET_FUNC_DATA (ctx, GumBoundsChecker *);

  if (old_address == NULL)
    return malloc (new_size);

  if (new_size == 0)
  {
    free (old_address);
    return NULL;
  }

  GUM_BOUNDS_CHECKER_LOCK ();

  if (!gum_page_pool_query_block_details (self->priv->page_pool, old_address,
      &old_block))
  {
    GUM_BOUNDS_CHECKER_UNLOCK ();

    goto fallback;
  }

  result = gum_bounds_checker_try_alloc (self, new_size, ctx);

  GUM_BOUNDS_CHECKER_UNLOCK ();

  if (result == NULL)
    result = malloc (new_size);

  if (result != NULL)
    memcpy (result, old_address, MIN (old_block.size, new_size));

  GUM_BOUNDS_CHECKER_LOCK ();
  success = gum_bounds_checker_try_free (self, old_address, ctx);
  g_assert (success);
  GUM_BOUNDS_CHECKER_UNLOCK ();

  return result;

fallback:
  return realloc (old_address, new_size);
}

static void
replacement_free (gpointer address)
{
  GumInvocationContext * ctx;
  GumBoundsChecker * self;
  gboolean freed;

  ctx = gum_interceptor_get_current_invocation ();
  self = GUM_RINCTX_GET_FUNC_DATA (ctx, GumBoundsChecker *);

  GUM_BOUNDS_CHECKER_LOCK ();
  freed = gum_bounds_checker_try_free (self, address, ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();

  if (!freed)
    free (address);
}

static gpointer
gum_bounds_checker_try_alloc (GumBoundsChecker * self,
                              guint size,
                              GumInvocationContext * ctx)
{
  GumBoundsCheckerPrivate * priv = self->priv;
  gpointer result;

  result = gum_page_pool_try_alloc (priv->page_pool, size);

  if (result != NULL && priv->backtracer_instance != NULL)
  {
    GumBlockDetails block;

    gum_page_pool_query_block_details (priv->page_pool, result, &block);

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_RW);

    g_assert_cmpuint (block.guard_size / 2,
        >=, sizeof (GumReturnAddressArray));
    priv->backtracer_interface->generate (priv->backtracer_instance,
        ctx->cpu_context, BLOCK_ALLOC_RETADDRS (&block));

    BLOCK_FREE_RETADDRS (&block)->len = 0;

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  return result;
}

static gboolean
gum_bounds_checker_try_free (GumBoundsChecker * self,
                             gpointer address,
                             GumInvocationContext * ctx)
{
  GumBoundsCheckerPrivate * priv = self->priv;
  gboolean freed;

  freed = gum_page_pool_try_free (priv->page_pool, address);

  if (freed && priv->backtracer_instance != NULL)
  {
    GumBlockDetails block;

    gum_page_pool_query_block_details (priv->page_pool, address, &block);

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_RW);

    g_assert_cmpuint (block.guard_size / 2,
        >=, sizeof (GumReturnAddressArray));
    priv->backtracer_interface->generate (priv->backtracer_instance,
        ctx->cpu_context, BLOCK_FREE_RETADDRS (&block));

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  return freed;
}

static void
gum_bounds_checker_handle_invalid_access (GumBoundsChecker * self,
                                          gpointer address)
{
  GumBoundsCheckerPrivate * priv = self->priv;
  GumBlockDetails block;
  GString * message;
  GumReturnAddressArray accessed_at = { 0, };

  if (priv->output == NULL)
    return;

  if (!gum_page_pool_query_block_details (priv->page_pool, address, &block))
    return;

  message = g_string_sized_new (300);

  g_string_append_printf (message,
      "Oops! %s block %p of %" G_GSIZE_MODIFIER "d bytes"
      " was accessed at offset %" G_GSIZE_MODIFIER "d",
      block.allocated ? "Heap" : "Freed",
      block.address,
      block.size,
      (gsize) (address - block.address));

  if (priv->backtracer_instance != NULL)
  {
    priv->backtracer_interface->generate (priv->backtracer_instance,
        NULL, &accessed_at);
  }

  if (accessed_at.len > 0)
  {
    g_string_append (message, " from:\n");
    gum_bounds_checker_append_backtrace (&accessed_at, message);
  }
  else
  {
    g_string_append_c (message, '\n');
  }

  if (priv->backtracer_instance != NULL)
  {
    GumReturnAddressArray * allocated_at, * freed_at;

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_READ);

    allocated_at = BLOCK_ALLOC_RETADDRS (&block);
    if (allocated_at->len > 0)
    {
      g_string_append (message, "Allocated at:\n");
      gum_bounds_checker_append_backtrace (allocated_at, message);
    }

    freed_at = BLOCK_FREE_RETADDRS (&block);
    if (freed_at->len > 0)
    {
      g_string_append (message, "Freed at:\n");
      gum_bounds_checker_append_backtrace (freed_at, message);
    }

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  priv->output (message->str, priv->output_user_data);

  g_string_free (message, TRUE);
}

static void
gum_bounds_checker_append_backtrace (const GumReturnAddressArray * arr,
                                     GString * s)
{
  guint i;

  for (i = 0; i != arr->len; i++)
  {
    GumReturnAddress addr = arr->items[i];
    GumReturnAddressDetails rad;

    if (gum_return_address_details_from_address (addr, &rad))
    {
      gchar * file_basename;

      file_basename = g_path_get_basename (rad.file_name);
      g_string_append_printf (s, "\t%p %s!%s %s:%u\n",
          rad.address,
          rad.module_name, rad.function_name,
          file_basename, rad.line_number);
      g_free (file_basename);
    }
    else
    {
      g_string_append_printf (s, "\t%p\n", addr);
    }
  }
}

#ifdef G_OS_WIN32

static gboolean
gum_bounds_checker_on_exception (EXCEPTION_RECORD * exception_record,
                                 CONTEXT * context,
                                 gpointer user_data)
{
  GSList * cur;

  (void) user_data;

  if (exception_record->ExceptionCode != STATUS_ACCESS_VIOLATION)
    return FALSE;

  /* must be a READ or WRITE */
  if (exception_record->ExceptionInformation[0] > 1)
    return FALSE;

  for (cur = gum_memaccess_instances; cur != NULL; cur = cur->next)
  {
    gum_bounds_checker_handle_invalid_access (
        GUM_BOUNDS_CHECKER_CAST (cur->data),
        (gpointer) exception_record->ExceptionInformation[1]);
  }

  return FALSE;
}

#else

static void
gum_bounds_checker_on_invalid_access (int sig,
                                      siginfo_t * siginfo,
                                      void * context)
{
  struct sigaction * action;
  GSList * cur;

  for (cur = gum_memaccess_instances; cur != NULL; cur = cur->next)
  {
    gum_bounds_checker_handle_invalid_access (
        GUM_BOUNDS_CHECKER_CAST (cur->data), siginfo->si_addr);
  }

  action =
      (sig == SIGSEGV) ? &gum_memaccess_old_sigsegv : &gum_memaccess_old_sigbus;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (action->sa_sigaction != NULL)
      action->sa_sigaction (sig, siginfo, context);
  }
  else
  {
    if (action->sa_handler != NULL)
      action->sa_handler (sig);
  }
}

#endif
