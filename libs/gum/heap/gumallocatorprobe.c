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

#include "gumallocatorprobe.h"

#include "guminterceptor.h"
#include "gumsymbolutil.h"

#include <gmodule.h>
#ifdef G_OS_WIN32
# ifdef _DEBUG
#  include <crtdbg.h>
#  define CRT_MODULE_NAME_EXT "d.dll"
# else
#  define CRT_MODULE_NAME_EXT ".dll"
# endif
# if _MSC_VER >= 1500
#  define CRT_MODULE_MS_VER "90"
# elif _MSC_VER >= 1400
#  define CRT_MODULE_MS_VER "80"
# else
#  error "Unsupported MS compiler"
# endif
# define CRT_MODULE_NAME "msvcr" CRT_MODULE_MS_VER CRT_MODULE_NAME_EXT
#else
# define CRT_MODULE_NAME "libc.so.6"
#endif

#define DEFAULT_ENABLE_COUNTERS FALSE

enum
{
  PROP_0,
  PROP_ALLOCATION_TRACKER,
  PROP_ENABLE_COUNTERS,
  PROP_MALLOC_COUNT,
  PROP_REALLOC_COUNT,
  PROP_FREE_COUNT
};

typedef struct _FunctionContext      FunctionContext;
typedef struct _HeapHandlers         HeapHandlers;
typedef struct _ThreadContext        ThreadContext;
typedef struct _AllocThreadContext   AllocThreadContext;
typedef struct _ReallocThreadContext ReallocThreadContext;

typedef void (* HeapEnterHandler) (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx);
typedef void (* HeapLeaveHandler) (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx);

struct _GumAllocatorProbePrivate
{
  gboolean disposed;

  GMutex * mutex;

  GumInterceptor * interceptor;
  GPtrArray * function_contexts;
  GumAllocationTracker * allocation_tracker;

  gboolean enable_counters;
  guint malloc_count;
  guint realloc_count;
  guint free_count;
};

#define GUM_ALLOCATOR_PROBE_GET_PRIVATE(o) ((o)->priv)

/*
 * Use the Debug CRT's recursive locks to avoid deadlocks.
 *
 * The problem is that on_enter() might get called with the CRT's heap lock
 * held, so if we then use our own lock we could deadlock because some other
 * thread might have taken our lock and is waiting for the CRT heap lock that
 * we're holding... This happens for C++ operator delete, which is implemented
 * using _free_dbg().
 */
#if defined (G_OS_WIN32) && defined (_DEBUG)
#define LOCK_INDEX_HEAP (4)
#ifdef GUM_STATIC
void _lock   (gint lock_index);
void _unlock (gint lock_index);
#else
__declspec(dllimport) void _lock   (gint lock_index);
__declspec(dllimport) void _unlock (gint lock_index);
#endif
#define GUM_ALLOCATOR_PROBE_LOCK()   _lock   (LOCK_INDEX_HEAP)
#define GUM_ALLOCATOR_PROBE_UNLOCK() _unlock (LOCK_INDEX_HEAP)
#else
#define GUM_ALLOCATOR_PROBE_LOCK()   g_mutex_lock   (priv->mutex)
#define GUM_ALLOCATOR_PROBE_UNLOCK() g_mutex_unlock (priv->mutex)
#endif

struct _ThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer function_specific_storage[4];
};

struct _HeapHandlers
{
  HeapEnterHandler enter_handler;
  HeapLeaveHandler leave_handler;
};

struct _FunctionContext
{
  HeapHandlers handlers;
  ThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

struct _AllocThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gsize size;
};

struct _ReallocThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer old_address;
  gsize new_size;
};

struct _FreeThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer address;
};

static void gum_allocator_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_allocator_probe_dispose (GObject * object);
static void gum_allocator_probe_finalize (GObject * object);

static void gum_allocator_probe_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_allocator_probe_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);

static void gum_allocator_probe_apply_default_suppressions (
    GumAllocatorProbe * self);

static void gum_allocator_probe_on_enter (GumInvocationListener * listener,
    GumInvocationContext * ctx);
static void gum_allocator_probe_on_leave (GumInvocationListener * listener,
    GumInvocationContext * ctx);
static gpointer gum_allocator_probe_provide_thread_data (
    GumInvocationListener * listener, gpointer function_instance_data,
    guint thread_id);

static void attach_to_function_by_name (GumAllocatorProbe * self,
    GModule * module, const gchar * function_name,
    const HeapHandlers * function_handlers);
static void attach_to_function (GumAllocatorProbe * self,
    gpointer function_address, const HeapHandlers * function_handlers);

static void gum_allocator_probe_on_malloc (GumAllocatorProbe * self,
    gpointer address, guint size, const GumCpuContext * cpu_context);
static void gum_allocator_probe_on_free (GumAllocatorProbe * self,
    gpointer address, const GumCpuContext * cpu_context);
static void gum_allocator_probe_on_realloc (GumAllocatorProbe * self,
    gpointer old_address, gpointer new_address, guint new_size,
    const GumCpuContext * cpu_context);

static void on_malloc_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_calloc_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_shared_xalloc_leave_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_enter_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_leave_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_free_enter_handler (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx);

#if defined (G_OS_WIN32) && defined (_DEBUG)

static void on_malloc_dbg_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_calloc_dbg_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_dbg_enter_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_free_dbg_enter_handler (GumAllocatorProbe * self,
    ThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);

static void decide_ignore_from_block_type (ThreadContext * thread_ctx,
    gint block_type);

#endif

G_DEFINE_TYPE_EXTENDED (GumAllocatorProbe,
                        gum_allocator_probe,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_allocator_probe_listener_iface_init));

static void
gum_allocator_probe_class_init (GumAllocatorProbeClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  g_type_class_add_private (klass, sizeof (GumAllocatorProbePrivate));

  object_class->set_property = gum_allocator_probe_set_property;
  object_class->get_property = gum_allocator_probe_get_property;
  object_class->dispose = gum_allocator_probe_dispose;
  object_class->finalize = gum_allocator_probe_finalize;

  pspec = g_param_spec_object ("allocation-tracker", "AllocationTracker",
      "AllocationTracker to use", GUM_TYPE_ALLOCATION_TRACKER,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ALLOCATION_TRACKER,
      pspec);

  pspec = g_param_spec_boolean ("enable-counters", "Enable Counters",
      "Enable counters for probed functions", DEFAULT_ENABLE_COUNTERS,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ENABLE_COUNTERS,
      pspec);

  pspec = g_param_spec_uint ("malloc-count", "Malloc Count",
      "Number of malloc() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MALLOC_COUNT, pspec);

  pspec = g_param_spec_uint ("realloc-count", "Realloc Count",
      "Number of realloc() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_REALLOC_COUNT, pspec);

  pspec = g_param_spec_uint ("free-count", "Free Count",
      "Number of free() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FREE_COUNT, pspec);
}

static void
gum_allocator_probe_listener_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = gum_allocator_probe_on_enter;
  iface->on_leave = gum_allocator_probe_on_leave;
  iface->provide_thread_data = gum_allocator_probe_provide_thread_data;
}

static void
gum_allocator_probe_init (GumAllocatorProbe * self)
{
  GumAllocatorProbePrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_ALLOCATOR_PROBE,
      GumAllocatorProbePrivate);

  priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  priv->mutex = g_mutex_new ();

  priv->interceptor = gum_interceptor_obtain ();
  priv->function_contexts = g_ptr_array_sized_new (3);

  priv->enable_counters = DEFAULT_ENABLE_COUNTERS;
}

static void
gum_allocator_probe_dispose (GObject * object)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    gum_allocator_probe_detach (self);

    if (priv->allocation_tracker != NULL)
    {
      g_object_unref (priv->allocation_tracker);
      priv->allocation_tracker = NULL;
    }

    if (priv->interceptor != NULL)
    {
      g_object_unref (priv->interceptor);
      priv->interceptor = NULL;
    }
  }

  G_OBJECT_CLASS (gum_allocator_probe_parent_class)->dispose (object);
}

static void
gum_allocator_probe_finalize (GObject * object)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  g_mutex_free (priv->mutex);

  G_OBJECT_CLASS (gum_allocator_probe_parent_class)->finalize (object);
}

static void
gum_allocator_probe_set_property (GObject * object,
                                  guint property_id,
                                  const GValue * value,
                                  GParamSpec * pspec)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  switch (property_id)
  {
    case PROP_ALLOCATION_TRACKER:
      if (priv->allocation_tracker != NULL)
        g_object_unref (priv->allocation_tracker);
      priv->allocation_tracker = g_value_dup_object (value);
      break;
    case PROP_ENABLE_COUNTERS:
      priv->enable_counters = g_value_get_boolean (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_allocator_probe_get_property (GObject * object,
                                  guint property_id,
                                  GValue * value,
                                  GParamSpec * pspec)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  switch (property_id)
  {
    case PROP_ALLOCATION_TRACKER:
      g_value_set_object (value, priv->allocation_tracker);
      break;
    case PROP_ENABLE_COUNTERS:
      g_value_set_boolean (value, priv->enable_counters);
      break;
    case PROP_MALLOC_COUNT:
      g_value_set_uint (value, priv->malloc_count);
      break;
    case PROP_REALLOC_COUNT:
      g_value_set_uint (value, priv->realloc_count);
      break;
    case PROP_FREE_COUNT:
      g_value_set_uint (value, priv->free_count);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_allocator_probe_apply_default_suppressions (GumAllocatorProbe * self)
{
  gpointer function_address;

  function_address = gum_find_function ("g_quark_new");
  if (function_address != NULL)
    gum_allocator_probe_suppress (self, function_address);

  gum_allocator_probe_suppress (self, g_quark_from_string);
  gum_allocator_probe_suppress (self, g_quark_from_static_string);

  gum_allocator_probe_suppress (self, g_signal_connect_data);
  gum_allocator_probe_suppress (self, g_signal_handlers_destroy);
  gum_allocator_probe_suppress (self, g_type_register_static);
  gum_allocator_probe_suppress (self, g_type_add_interface_static);
  gum_allocator_probe_suppress (self, g_param_spec_pool_insert);

  function_address = gum_find_function ("instance_real_class_set");
  if (function_address != NULL)
    gum_allocator_probe_suppress (self, function_address);

  function_address = gum_find_function ("instance_real_class_remove");
  if (function_address != NULL)
    gum_allocator_probe_suppress (self, function_address);

  function_address = gum_find_function ("gst_object_set_name_default");
  if (function_address != NULL)
    gum_allocator_probe_suppress (self, function_address);
}

static void
gum_allocator_probe_on_enter (GumInvocationListener * listener,
                              GumInvocationContext * ctx)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE_CAST (listener);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  FunctionContext * function_ctx = (FunctionContext *) ctx->instance_data;
  ThreadContext * base_thread_ctx = (ThreadContext *) ctx->thread_data;

  gum_interceptor_ignore_caller (priv->interceptor);

  if (function_ctx != NULL)
  {
    GUM_ALLOCATOR_PROBE_LOCK ();

    base_thread_ctx->ignored = FALSE;

    function_ctx->handlers.enter_handler (self, ctx->thread_data, ctx);
  }
}

static void
gum_allocator_probe_on_leave (GumInvocationListener * listener,
                              GumInvocationContext * ctx)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE_CAST (listener);
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  FunctionContext * function_ctx = (FunctionContext *) ctx->instance_data;
  ThreadContext * base_ctx = (ThreadContext *) ctx->thread_data;

  if (function_ctx != NULL)
  {
    if (!base_ctx->ignored)
    {
      if (function_ctx->handlers.leave_handler != NULL)
        function_ctx->handlers.leave_handler (self, ctx->thread_data, ctx);
    }

    GUM_ALLOCATOR_PROBE_UNLOCK ();
  }

  gum_interceptor_unignore_caller (priv->interceptor);
}

static gpointer
gum_allocator_probe_provide_thread_data (GumInvocationListener * listener,
                                         gpointer function_instance_data,
                                         guint thread_id)
{
  FunctionContext * function_ctx = (FunctionContext *) function_instance_data;
  guint i;

  if (function_ctx == NULL)
    return NULL;

  i = g_atomic_int_exchange_and_add (&function_ctx->thread_context_count, 1);
  g_assert (i < G_N_ELEMENTS (function_ctx->thread_contexts));
  return &function_ctx->thread_contexts[i];
}

GumAllocatorProbe *
gum_allocator_probe_new (void)
{
  return GUM_ALLOCATOR_PROBE_CAST (
      g_object_new (GUM_TYPE_ALLOCATOR_PROBE, NULL));
}

typedef struct
{
  const gchar * name;
  gpointer local_address;
  HeapHandlers handlers;
} ProbeHandler;

static const ProbeHandler probe_handlers[] =
{
  {
    "malloc", malloc,
    {
      (HeapEnterHandler) on_malloc_enter_handler,
      (HeapLeaveHandler) on_shared_xalloc_leave_handler
    }
  },

  {
    "calloc", calloc,
    {
      (HeapEnterHandler) on_calloc_enter_handler,
      (HeapLeaveHandler) on_shared_xalloc_leave_handler
    }
  },

  {
    "realloc", realloc,
    {
      (HeapEnterHandler) on_realloc_enter_handler,
      (HeapLeaveHandler) on_realloc_leave_handler
    }
  },

  {
    "free", free,
    {
      (HeapEnterHandler) on_free_enter_handler,
      NULL
    }
  },

#if defined (G_OS_WIN32) && defined (_DEBUG)
  {
    "_malloc_dbg", _malloc_dbg,
    {
      (HeapEnterHandler) on_malloc_dbg_enter_handler,
      (HeapLeaveHandler) on_shared_xalloc_leave_handler
    }
  },

  {
    "_calloc_dbg", _calloc_dbg,
    {
      (HeapEnterHandler) on_calloc_dbg_enter_handler,
      (HeapLeaveHandler) on_shared_xalloc_leave_handler
    }
  },

  {
    "_realloc_dbg", _realloc_dbg,
    {
      (HeapEnterHandler) on_realloc_dbg_enter_handler,
      (HeapLeaveHandler) on_realloc_leave_handler
    }
  },

  {
    "_free_dbg", _free_dbg,
    {
      (HeapEnterHandler) on_free_dbg_enter_handler,
      NULL
    }
  }
#endif
};

void
gum_allocator_probe_attach (GumAllocatorProbe * self)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  GModule * module;
  guint i;

  gum_interceptor_ignore_caller (priv->interceptor);

  /*
   * TODO: we only intercept the CRT currently in use for now.
   */
  module = g_module_open (CRT_MODULE_NAME, (GModuleFlags) 0);
  if (module != NULL)
  {
    for (i = 0; i != G_N_ELEMENTS (probe_handlers); i++)
    {
      attach_to_function_by_name (self, module, probe_handlers[i].name,
          &probe_handlers[i].handlers);
    }

    g_module_close (module);
  }
  else
  {
    for (i = 0; i != G_N_ELEMENTS (probe_handlers); i++)
    {
      attach_to_function (self, probe_handlers[i].local_address,
          &probe_handlers[i].handlers);
    }
  }

  gum_allocator_probe_apply_default_suppressions (self);

  gum_interceptor_unignore_caller (priv->interceptor);
}

void
gum_allocator_probe_detach (GumAllocatorProbe * self)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  guint i;

  gum_interceptor_ignore_caller (priv->interceptor);

  gum_interceptor_detach_listener (priv->interceptor,
      GUM_INVOCATION_LISTENER (self));

  for (i = 0; i < priv->function_contexts->len; i++)
  {
    FunctionContext * function_ctx =
        g_ptr_array_index (priv->function_contexts, i);
    g_free (function_ctx);
  }

  g_ptr_array_set_size (priv->function_contexts, 0);

  priv->malloc_count = 0;
  priv->realloc_count = 0;
  priv->free_count = 0;

  gum_interceptor_unignore_caller (priv->interceptor);
}

static void
attach_to_function_by_name (GumAllocatorProbe * self,
                            GModule * module,
                            const gchar * function_name,
                            const HeapHandlers * function_handlers)
{
  gboolean success;
  gpointer function_address;

  success = g_module_symbol (module, function_name, &function_address);
  g_assert (success);

  attach_to_function (self, function_address, function_handlers);
}

static void
attach_to_function (GumAllocatorProbe * self,
                    gpointer function_address,
                    const HeapHandlers * function_handlers)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  GumInvocationListener * listener = GUM_INVOCATION_LISTENER (self);
  FunctionContext * function_ctx;
  GumAttachReturn attach_ret;

  function_ctx = g_new0 (FunctionContext, 1);
  function_ctx->handlers = *function_handlers;
  g_ptr_array_add (priv->function_contexts, function_ctx);

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      function_address, listener, function_ctx);
  g_assert (attach_ret == GUM_ATTACH_OK);
}

void
gum_allocator_probe_suppress (GumAllocatorProbe * self,
                              gpointer function_address)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);
  GumInvocationListener * listener = GUM_INVOCATION_LISTENER (self);
  GumAttachReturn attach_ret;

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      function_address, listener, NULL);
  g_assert (attach_ret == GUM_ATTACH_OK);
}

static void
gum_allocator_probe_on_malloc (GumAllocatorProbe * self,
                               gpointer address,
                               guint size,
                               const GumCpuContext * cpu_context)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  if (priv->enable_counters)
    priv->malloc_count++;

  if (priv->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_malloc_full (priv->allocation_tracker, address,
        size, cpu_context);
  }
}

static void
gum_allocator_probe_on_free (GumAllocatorProbe * self,
                             gpointer address,
                             const GumCpuContext * cpu_context)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  if (priv->enable_counters)
    priv->free_count++;

  if (priv->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_free_full (priv->allocation_tracker, address,
        cpu_context);
  }
}

static void
gum_allocator_probe_on_realloc (GumAllocatorProbe * self,
                                gpointer old_address,
                                gpointer new_address,
                                guint new_size,
                                const GumCpuContext * cpu_context)
{
  GumAllocatorProbePrivate * priv = GUM_ALLOCATOR_PROBE_GET_PRIVATE (self);

  if (priv->enable_counters)
    priv->realloc_count++;

  if (priv->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_realloc_full (priv->allocation_tracker,
        old_address, new_address, new_size, cpu_context);
  }
}

static void
on_malloc_enter_handler (GumAllocatorProbe * self,
                         AllocThreadContext * thread_ctx,
                         GumInvocationContext * invocation_ctx)
{
  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->size =
      (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 0);
}

static void
on_calloc_enter_handler (GumAllocatorProbe * self,
                         AllocThreadContext * thread_ctx,
                         GumInvocationContext * invocation_ctx)
{
  gsize num, size;

  num = (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 0);
  size = (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 1);

  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->size = num * size;
}

static void
on_shared_xalloc_leave_handler (GumAllocatorProbe * self,
                                AllocThreadContext * thread_ctx,
                                GumInvocationContext * invocation_ctx)
{
  gpointer return_value;

  return_value = gum_invocation_context_get_return_value (invocation_ctx);

  if (return_value != NULL)
  {
    gum_allocator_probe_on_malloc (self, return_value, thread_ctx->size,
        &thread_ctx->cpu_context);
  }
}

static void
on_realloc_enter_handler (GumAllocatorProbe * self,
                          ReallocThreadContext * thread_ctx,
                          GumInvocationContext * invocation_ctx)
{
  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->old_address =
      gum_invocation_context_get_nth_argument (invocation_ctx, 0);
  thread_ctx->new_size =
      (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 1);
}

static void
on_realloc_leave_handler (GumAllocatorProbe * self,
                          ReallocThreadContext * thread_ctx,
                          GumInvocationContext * invocation_ctx)
{
  gpointer return_value;

  return_value = gum_invocation_context_get_return_value (invocation_ctx);

  if (return_value != NULL)
  {
    gum_allocator_probe_on_realloc (self, thread_ctx->old_address,
        return_value, thread_ctx->new_size, &thread_ctx->cpu_context);
  }
}

static void
on_free_enter_handler (GumAllocatorProbe * self,
                       gpointer thread_ctx,
                       GumInvocationContext * invocation_ctx)
{
  gpointer address;

  address = gum_invocation_context_get_nth_argument (invocation_ctx, 0);

  gum_allocator_probe_on_free (self, address, invocation_ctx->cpu_context);
}

#if defined (G_OS_WIN32) && defined (_DEBUG)

static void
on_malloc_dbg_enter_handler (GumAllocatorProbe * self,
                             AllocThreadContext * thread_ctx,
                             GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type =
      (gint) gum_invocation_context_get_nth_argument (invocation_ctx, 1);

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_malloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_calloc_dbg_enter_handler (GumAllocatorProbe * self,
                             AllocThreadContext * thread_ctx,
                             GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type =
      (gint) gum_invocation_context_get_nth_argument (invocation_ctx, 2);

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_calloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_realloc_dbg_enter_handler (GumAllocatorProbe * self,
                              ReallocThreadContext * thread_ctx,
                              GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type =
      (gint) gum_invocation_context_get_nth_argument (invocation_ctx, 2);

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_realloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_free_dbg_enter_handler (GumAllocatorProbe * self,
                           ThreadContext * thread_ctx,
                           GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type =
      (gint) gum_invocation_context_get_nth_argument (invocation_ctx, 1);

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_free_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
decide_ignore_from_block_type (ThreadContext * thread_ctx,
                               gint block_type)
{
  thread_ctx->ignored = (block_type != _NORMAL_BLOCK);
}

#endif /* defined (G_OS_WIN32) && defined (_DEBUG) */
