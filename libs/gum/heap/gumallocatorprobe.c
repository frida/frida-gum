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

#include "gumallocatorprobe-priv.h"
#include "guminterceptor.h"
#include "gumsymbolutil.h"

#include <gmodule.h>

#define GUM_DBGCRT_NORMAL_BLOCK (1)

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
    GumInvocationContext * context);
static void gum_allocator_probe_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

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

G_DEFINE_TYPE_EXTENDED (GumAllocatorProbe,
                        gum_allocator_probe,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_allocator_probe_listener_iface_init));

G_LOCK_DEFINE (_gum_allocator_probe_ignored_functions);
static GArray * _gum_allocator_probe_ignored_functions = NULL;

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

void
_gum_allocator_probe_deinit (void)
{
  if (_gum_allocator_probe_ignored_functions != NULL)
  {
    g_array_free (_gum_allocator_probe_ignored_functions, TRUE);
    _gum_allocator_probe_ignored_functions = NULL;
  }
}

static void
gum_allocator_probe_listener_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_allocator_probe_on_enter;
  iface->on_leave = gum_allocator_probe_on_leave;
}

static void
gum_allocator_probe_init (GumAllocatorProbe * self)
{
  GumAllocatorProbePrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_ALLOCATOR_PROBE,
      GumAllocatorProbePrivate);

  priv = self->priv;

  priv->mutex = g_mutex_new ();

  priv->interceptor = gum_interceptor_obtain ();
  priv->function_contexts = g_ptr_array_sized_new (3);

  priv->enable_counters = DEFAULT_ENABLE_COUNTERS;
}

static void
gum_allocator_probe_dispose (GObject * object)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = self->priv;

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
  GumAllocatorProbePrivate * priv = self->priv;

  g_mutex_free (priv->mutex);

  g_ptr_array_free (priv->function_contexts, TRUE);

  G_OBJECT_CLASS (gum_allocator_probe_parent_class)->finalize (object);
}

static void
gum_allocator_probe_set_property (GObject * object,
                                  guint property_id,
                                  const GValue * value,
                                  GParamSpec * pspec)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);
  GumAllocatorProbePrivate * priv = self->priv;

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
  GumAllocatorProbePrivate * priv = self->priv;

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

static gboolean
gum_allocator_probe_add_suppression_addresses_if_glib (const gchar * name,
                                                       gpointer address,
                                                       const gchar * path,
                                                       gpointer user_data)
{
  static const gchar * glib_function_name[] = {
    "g_quark_from_string",
    "g_quark_from_static_string",
    NULL
  };
  static const gchar * gobject_function_name[] = {
    "g_signal_connect_data",
    "g_signal_handlers_destroy",
    "g_type_register_static",
    "g_type_add_interface_static",
    "g_param_spec_pool_insert",
    NULL
  };
  GArray * ignored = (GArray *) user_data;
  gchar * name_lowercase;
  static const gchar ** function_name;

  (void) address;

  name_lowercase = g_ascii_strdown (name, -1);

  if (g_strstr_len (name_lowercase, -1, "glib-2.0") != NULL)
    function_name = glib_function_name;
  else if (g_strstr_len (name_lowercase, -1, "gobject-2.0") != NULL)
    function_name = gobject_function_name;
  else
    function_name = NULL;

  if (function_name != NULL)
  {
    GModule * module;
    guint i;

    module = g_module_open (path, (GModuleFlags) 0);

    for (i = 0; function_name[i] != NULL; i++)
    {
      gpointer address;
      gboolean found;

      found = g_module_symbol (module, function_name[i], &address);
      g_assert (found);

      g_array_append_val (ignored, address);
    }

    g_module_close (module);
  }

  g_free (name_lowercase);

  return TRUE;
}

static void
gum_allocator_probe_apply_default_suppressions (GumAllocatorProbe * self)
{
  GArray * ignored;
  guint i;

  G_LOCK (_gum_allocator_probe_ignored_functions);

  if (_gum_allocator_probe_ignored_functions == NULL)
  {
    static const gchar * internal_function_name[] = {
        "g_quark_new",
        "instance_real_class_set",
        "instance_real_class_remove",
        "gst_object_set_name_default"
    };

    ignored = g_array_new (FALSE, FALSE, sizeof (gpointer));

    for (i = 0; i != G_N_ELEMENTS (internal_function_name); i++)
    {
      GArray * addrs = gum_find_functions_named (internal_function_name[i]);
      if (addrs->len != 0)
        g_array_append_vals (ignored, addrs->data, addrs->len);
      g_array_free (addrs, TRUE);
    }

    gum_process_enumerate_modules (
        gum_allocator_probe_add_suppression_addresses_if_glib, ignored);

    _gum_allocator_probe_ignored_functions = ignored;
  }
  else
  {
    ignored = _gum_allocator_probe_ignored_functions;
  }

  G_UNLOCK (_gum_allocator_probe_ignored_functions);

  for (i = 0; i != ignored->len; i++)
    gum_allocator_probe_suppress (self, g_array_index (ignored, gpointer, i));

  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_quark_from_string));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_quark_from_static_string));

  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_signal_connect_data));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_signal_handlers_destroy));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_type_register_static));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_type_add_interface_static));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_param_spec_pool_insert));
}

static void
gum_allocator_probe_on_enter (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE_CAST (listener);
  GumAllocatorProbePrivate * priv = self->priv;
  FunctionContext * function_ctx;

  function_ctx = GUM_LINCTX_GET_FUNC_DATA (context, FunctionContext *);

  gum_interceptor_ignore_current_thread (priv->interceptor);

  if (function_ctx != NULL)
  {
    ThreadContext * base_thread_ctx;

    base_thread_ctx = GUM_LINCTX_GET_FUNC_INVDATA (context, ThreadContext);
    base_thread_ctx->ignored = FALSE;

    function_ctx->handlers.enter_handler (self, base_thread_ctx, context);
  }
}

static void
gum_allocator_probe_on_leave (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE_CAST (listener);
  GumAllocatorProbePrivate * priv = self->priv;
  FunctionContext * function_ctx;

  function_ctx = GUM_LINCTX_GET_FUNC_DATA (context, FunctionContext *);

  if (function_ctx != NULL)
  {
    ThreadContext * base_thread_ctx;

    base_thread_ctx = GUM_LINCTX_GET_FUNC_INVDATA (context, ThreadContext);

    if (!base_thread_ctx->ignored)
    {
      if (function_ctx->handlers.leave_handler != NULL)
      {
        function_ctx->handlers.leave_handler (self, base_thread_ctx,
            context);
      }
    }
  }

  gum_interceptor_unignore_current_thread (priv->interceptor);
}

GumAllocatorProbe *
gum_allocator_probe_new (void)
{
  return GUM_ALLOCATOR_PROBE_CAST (
      g_object_new (GUM_TYPE_ALLOCATOR_PROBE, NULL));
}

static const HeapHandlers gum_malloc_handlers =
{
  (HeapEnterHandler) on_malloc_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum_calloc_handlers =
{
  (HeapEnterHandler) on_calloc_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum_realloc_handlers =
{
  (HeapEnterHandler) on_realloc_enter_handler,
  (HeapLeaveHandler) on_realloc_leave_handler
};

static const HeapHandlers gum_free_handlers =
{
  (HeapEnterHandler) on_free_enter_handler,
  NULL
};

static const HeapHandlers gum__malloc_dbg_handlers =
{
  (HeapEnterHandler) on_malloc_dbg_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum__calloc_dbg_handlers =
{
  (HeapEnterHandler) on_calloc_dbg_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum__realloc_dbg_handlers =
{
  (HeapEnterHandler) on_realloc_dbg_enter_handler,
  (HeapLeaveHandler) on_realloc_leave_handler
};

static const HeapHandlers gum__free_dbg_handlers =
{
  (HeapEnterHandler) on_free_dbg_enter_handler,
  NULL
};

void
gum_allocator_probe_attach (GumAllocatorProbe * self)
{
  GumHeapApiList * apis = gum_process_find_heap_apis ();
  gum_allocator_probe_attach_to_apis (self, apis);
  gum_heap_api_list_free (apis);
}

#define GUM_ATTACH_TO_API_FUNC(name) \
    attach_to_function (self, GUM_FUNCPTR_TO_POINTER (api->name), \
        &gum_##name##_handlers)

void
gum_allocator_probe_attach_to_apis (GumAllocatorProbe * self,
                                    const GumHeapApiList * apis)
{
  GumAllocatorProbePrivate * priv = self->priv;
  guint i;

  gum_interceptor_ignore_current_thread (priv->interceptor);

  for (i = 0; i != apis->len; i++)
  {
    const GumHeapApi * api = gum_heap_api_list_get_nth (apis, i);

    GUM_ATTACH_TO_API_FUNC (malloc);
    GUM_ATTACH_TO_API_FUNC (calloc);
    GUM_ATTACH_TO_API_FUNC (realloc);
    GUM_ATTACH_TO_API_FUNC (free);

    if (api->_malloc_dbg != NULL)
    {
      GUM_ATTACH_TO_API_FUNC (_malloc_dbg);
      GUM_ATTACH_TO_API_FUNC (_calloc_dbg);
      GUM_ATTACH_TO_API_FUNC (_realloc_dbg);
      GUM_ATTACH_TO_API_FUNC (_free_dbg);
    }
  }

  gum_allocator_probe_apply_default_suppressions (self);

  gum_interceptor_unignore_current_thread (priv->interceptor);
}

void
gum_allocator_probe_detach (GumAllocatorProbe * self)
{
  GumAllocatorProbePrivate * priv = self->priv;
  guint i;

  gum_interceptor_ignore_current_thread (priv->interceptor);

  gum_interceptor_detach_listener (priv->interceptor,
      GUM_INVOCATION_LISTENER (self));

  for (i = 0; i < priv->function_contexts->len; i++)
  {
    FunctionContext * function_ctx = (FunctionContext *)
        g_ptr_array_index (priv->function_contexts, i);
    g_free (function_ctx);
  }

  g_ptr_array_set_size (priv->function_contexts, 0);

  priv->malloc_count = 0;
  priv->realloc_count = 0;
  priv->free_count = 0;

  gum_interceptor_unignore_current_thread (priv->interceptor);
}

static void
attach_to_function (GumAllocatorProbe * self,
                    gpointer function_address,
                    const HeapHandlers * function_handlers)
{
  GumAllocatorProbePrivate * priv = self->priv;
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
  GumAllocatorProbePrivate * priv = self->priv;
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
  GumAllocatorProbePrivate * priv = self->priv;

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
  GumAllocatorProbePrivate * priv = self->priv;

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
  GumAllocatorProbePrivate * priv = self->priv;

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
  (void) self;

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

  (void) self;

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
  (void) self;

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

  (void) thread_ctx;

  address = gum_invocation_context_get_nth_argument (invocation_ctx, 0);

  gum_allocator_probe_on_free (self, address, invocation_ctx->cpu_context);
}

static void
on_malloc_dbg_enter_handler (GumAllocatorProbe * self,
                             AllocThreadContext * thread_ctx,
                             GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 1));

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

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 2));

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

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 2));

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

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 1));

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_free_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
decide_ignore_from_block_type (ThreadContext * thread_ctx,
                               gint block_type)
{
  thread_ctx->ignored = (block_type != GUM_DBGCRT_NORMAL_BLOCK);
}
