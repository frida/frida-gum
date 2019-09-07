/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukinterceptor.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

#define GUM_DUK_INVOCATION_LISTENER_CAST(obj) \
    ((GumDukInvocationListener *) (obj))
#define GUM_DUK_TYPE_JS_CALL_LISTENER (gum_duk_js_call_listener_get_type ())
#define GUM_DUK_TYPE_JS_PROBE_LISTENER (gum_duk_js_probe_listener_get_type ())
#define GUM_DUK_TYPE_C_CALL_LISTENER (gum_duk_c_call_listener_get_type ())
#define GUM_DUK_TYPE_C_PROBE_LISTENER (gum_duk_c_probe_listener_get_type ())

typedef struct _GumDukInvocationListener GumDukInvocationListener;
typedef struct _GumDukJSCallListener GumDukJSCallListener;
typedef struct _GumDukJSCallListenerClass GumDukJSCallListenerClass;
typedef struct _GumDukJSProbeListener GumDukJSProbeListener;
typedef struct _GumDukJSProbeListenerClass GumDukJSProbeListenerClass;
typedef struct _GumDukCCallListener GumDukCCallListener;
typedef struct _GumDukCCallListenerClass GumDukCCallListenerClass;
typedef struct _GumDukCProbeListener GumDukCProbeListener;
typedef struct _GumDukCProbeListenerClass GumDukCProbeListenerClass;
typedef struct _GumDukInvocationState GumDukInvocationState;
typedef struct _GumDukReplaceEntry GumDukReplaceEntry;

struct _GumDukInvocationListener
{
  GObject parent;

  GumDukHeapPtr object;
  union
  {
    gpointer on_enter;
    GumDukHeapPtr on_enter_js;
    void (* on_enter_c) (GumInvocationContext * ic);
  };
  union
  {
    gpointer on_leave;
    GumDukHeapPtr on_leave_js;
    void (* on_leave_c) (GumInvocationContext * ic);
  };

  GumDukInterceptor * module;
};

struct _GumDukJSCallListener
{
  GumDukInvocationListener listener;
};

struct _GumDukJSCallListenerClass
{
  GObjectClass parent_class;
};

struct _GumDukJSProbeListener
{
  GumDukInvocationListener listener;
};

struct _GumDukJSProbeListenerClass
{
  GObjectClass parent_class;
};

struct _GumDukCCallListener
{
  GumDukInvocationListener listener;
};

struct _GumDukCCallListenerClass
{
  GObjectClass parent_class;
};

struct _GumDukCProbeListener
{
  GumDukInvocationListener listener;
};

struct _GumDukCProbeListenerClass
{
  GObjectClass parent_class;
};

struct _GumDukInvocationState
{
  GumDukInvocationContext * jic;
};

struct _GumDukInvocationArgs
{
  GumDukHeapPtr object;
  GumInvocationContext * ic;

  GumDukCore * core;
};

struct _GumDukInvocationReturnValue
{
  GumDukNativePointer parent;

  GumDukHeapPtr object;
  GumInvocationContext * ic;

  GumDukCore * core;
};

struct _GumDukReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumDukHeapPtr replacement;
  GumDukCore * core;
};

static gboolean gum_duk_interceptor_on_flush_timer_tick (
    GumDukInterceptor * self);

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_duk_invocation_listener_destroy (
    GumDukInvocationListener * listener);
static void gum_duk_interceptor_detach (GumDukInterceptor * self,
    GumDukInvocationListener * listener);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_duk_replace_entry_free (GumDukReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_listener_construct)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)

static void gum_duk_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_js_call_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumDukJSCallListener,
                        gum_duk_js_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_duk_js_call_listener_iface_init))

static void gum_duk_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_js_probe_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumDukJSProbeListener,
                        gum_duk_js_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_duk_js_probe_listener_iface_init))

static void gum_duk_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_c_call_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumDukCCallListener,
                        gum_duk_c_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_duk_c_call_listener_iface_init))

static void gum_duk_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_c_probe_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumDukCProbeListener,
                        gum_duk_c_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_duk_c_probe_listener_iface_init))

static GumDukInvocationContext * gum_duk_invocation_context_new (
    GumDukInterceptor * parent);
static void gum_duk_invocation_context_release (GumDukInvocationContext * self);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_property)

static GumDukInvocationArgs * gum_duk_invocation_args_new (
    GumDukInterceptor * parent);
static void gum_duk_invocation_args_release (GumDukInvocationArgs * self);
static void gum_duk_invocation_args_reset (GumDukInvocationArgs * self,
    GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_args_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_args_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static GumDukInvocationReturnValue * gum_duk_invocation_return_value_new (
    GumDukInterceptor * parent);
static void gum_duk_invocation_return_value_release (
    GumDukInvocationReturnValue * self);
static void gum_duk_invocation_return_value_reset (
    GumDukInvocationReturnValue * self, GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_return_value_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_return_value_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

static GumDukInvocationArgs * gum_duk_interceptor_obtain_invocation_args (
    GumDukInterceptor * self);
static void gum_duk_interceptor_release_invocation_args (
    GumDukInterceptor * self, GumDukInvocationArgs * args);
static GumDukInvocationReturnValue *
gum_duk_interceptor_obtain_invocation_return_value (GumDukInterceptor * self);
static void gum_duk_interceptor_release_invocation_return_value (
    GumDukInterceptor * self, GumDukInvocationReturnValue * retval);

static const duk_function_list_entry gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach, 3 },
  { "detachAll", gumjs_interceptor_detach_all, 0 },
  { "_replace", gumjs_interceptor_replace, 3 },
  { "revert", gumjs_interceptor_revert, 1 },
  { "flush", gumjs_interceptor_flush, 0 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_invocation_listener_functions[] =
{
  { "detach", gumjs_invocation_listener_detach, 0 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_invocation_context_values[] =
{
  {
    "returnAddress",
    gumjs_invocation_context_get_return_address,
    NULL
  },
  {
    "context",
    gumjs_invocation_context_get_cpu_context,
    NULL
  },
  {
    GUMJS_SYSTEM_ERROR_FIELD,
    gumjs_invocation_context_get_system_error,
    gumjs_invocation_context_set_system_error
  },
  {
    "threadId",
    gumjs_invocation_context_get_thread_id,
    NULL
  },
  {
    "depth",
    gumjs_invocation_context_get_depth,
    NULL
  },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_invocation_return_value_functions[] =
{
  { "replace", gumjs_invocation_return_value_replace, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_interceptor_init (GumDukInterceptor * self,
                           GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_invocation_listener_destroy);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_replace_entry_free);
  self->flush_timer = NULL;

  _gum_duk_store_module_data (ctx, "interceptor", self);

  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_interceptor_functions);
  duk_put_global_string (ctx, "Interceptor");

  duk_push_c_function (ctx, gumjs_invocation_listener_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_invocation_listener_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->invocation_listener = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationListener");

  duk_push_c_function (ctx, gumjs_invocation_context_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_invocation_context_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->invocation_context = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationContext");
  _gum_duk_add_properties_to_class (ctx, "InvocationContext",
      gumjs_invocation_context_values);

  duk_push_c_function (ctx, gumjs_invocation_args_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_invocation_args_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->invocation_args = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationArgs");

  _gum_duk_create_subclass (ctx, "NativePointer", "InvocationReturnValue",
      gumjs_invocation_return_value_construct, 1, NULL);
  duk_get_global_string (ctx, "InvocationReturnValue");
  duk_get_prop_string (ctx, -1, "prototype");
  duk_push_c_function (ctx, gumjs_invocation_return_value_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_function_list (ctx, -1, gumjs_invocation_return_value_functions);
  duk_pop (ctx);
  self->invocation_retval = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  self->cached_invocation_context = gum_duk_invocation_context_new (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args = gum_duk_invocation_args_new (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_return_value = gum_duk_invocation_return_value_new (
      self);
  self->cached_invocation_return_value_in_use = FALSE;
}

void
_gum_duk_interceptor_flush (GumDukInterceptor * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  _gum_duk_scope_suspend (&scope);

  flushed = gum_interceptor_flush (self->interceptor);

  _gum_duk_scope_resume (&scope);

  if (!flushed && self->flush_timer == NULL)
  {
    GSource * source;

    source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_duk_interceptor_on_flush_timer_tick, self, NULL);
    self->flush_timer = source;

    _gum_duk_core_pin (core);
    _gum_duk_scope_suspend (&scope);

    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);

    _gum_duk_scope_resume (&scope);
  }
}

static gboolean
gum_duk_interceptor_on_flush_timer_tick (GumDukInterceptor * self)
{
  gboolean flushed;

  flushed = gum_interceptor_flush (self->interceptor);
  if (flushed)
  {
    GumDukCore * core = self->core;
    GumDukScope scope;

    _gum_duk_scope_enter (&scope, core);
    _gum_duk_core_unpin (core);
    self->flush_timer = NULL;
    _gum_duk_scope_leave (&scope);
  }

  return !flushed;
}

void
_gum_duk_interceptor_dispose (GumDukInterceptor * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  g_assert (self->flush_timer == NULL);

  gum_duk_invocation_context_release (self->cached_invocation_context);
  gum_duk_invocation_args_release (self->cached_invocation_args);
  gum_duk_invocation_return_value_release (
      self->cached_invocation_return_value);

  _gum_duk_release_heapptr (ctx, self->invocation_listener);
  _gum_duk_release_heapptr (ctx, self->invocation_context);
  _gum_duk_release_heapptr (ctx, self->invocation_args);
  _gum_duk_release_heapptr (ctx, self->invocation_retval);
}

void
_gum_duk_interceptor_finalize (GumDukInterceptor * self)
{
  g_clear_pointer (&self->invocation_listeners, g_hash_table_unref);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

static GumDukInterceptor *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "interceptor");
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  GumDukInterceptor * self;
  GumDukCore * core = args->core;
  gpointer target, on_enter, on_leave;
  GumDukInvocationListener * listener;
  gpointer listener_function_data;
  GumAttachReturn attach_ret;

  self = gumjs_module_from_args (args);

  duk_push_heapptr (ctx, core->native_pointer);

  if (duk_is_function (ctx, 1))
  {
    target = _gum_duk_require_pointer (ctx, 0, core);
    on_enter = duk_require_heapptr (ctx, 1);
    on_leave = NULL;

    listener = g_object_new (GUM_DUK_TYPE_JS_PROBE_LISTENER, NULL);
  }
  else if (duk_instanceof (ctx, 1, -1))
  {
    target = _gum_duk_require_pointer (ctx, 0, core);
    on_enter = _gum_duk_require_pointer (ctx, 1, core);
    on_leave = NULL;

    listener = g_object_new (GUM_DUK_TYPE_C_PROBE_LISTENER, NULL);
  }
  else
  {
    gpointer on_enter_js, on_enter_c;
    gpointer on_leave_js, on_leave_c;

    _gum_duk_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c);

    if (on_enter_js != NULL || on_leave_js != NULL)
    {
      on_enter = on_enter_js;
      on_leave = on_leave_js;

      listener = g_object_new (GUM_DUK_TYPE_JS_CALL_LISTENER, NULL);
    }
    else
    {
      on_enter = on_enter_c;
      on_leave = on_leave_c;

      listener = g_object_new (GUM_DUK_TYPE_C_CALL_LISTENER, NULL);
    }
  }

  duk_pop (ctx);

  if (!duk_is_undefined (ctx, 2))
    listener_function_data = _gum_duk_require_pointer (ctx, 2, core);
  else
    listener_function_data = NULL;

  listener->on_enter = on_enter;
  listener->on_leave = on_leave;
  listener->module = self;

  attach_ret = gum_interceptor_attach (self->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  duk_push_heapptr (ctx, self->invocation_listener);
  duk_new (ctx, 0);

  listener->object = _gum_duk_require_heapptr (ctx, -1);

  _gum_duk_put_data (ctx, -1, listener);

  duk_dup (ctx, 1);
  duk_put_prop_string (ctx, -2, DUK_HIDDEN_SYMBOL ("resource"));

  g_hash_table_add (self->invocation_listeners, listener);

  return 1;

unable_to_attach:
  {
    g_object_unref (listener);

    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gum_duk_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gum_duk_throw (ctx, "already attached to this function");
      case GUM_ATTACH_POLICY_VIOLATION:
        _gum_duk_throw (ctx, "not permitted by code-signing policy");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_duk_invocation_listener_destroy (GumDukInvocationListener * listener)
{
  gum_interceptor_detach (listener->module->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_duk_interceptor_detach (GumDukInterceptor * self,
                            GumDukInvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumDukInterceptor * self = gumjs_module_from_args (args);

  g_hash_table_remove_all (self->invocation_listeners);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumDukInterceptor * self;
  GumDukCore * core = args->core;
  gpointer target, replacement_function, replacement_data;
  GumDukHeapPtr replacement_value;
  GumDukReplaceEntry * entry;
  GumReplaceReturn replace_ret;

  self = gumjs_module_from_args (args);

  replacement_data = NULL;
  _gum_duk_args_parse (args, "pO|p", &target, &replacement_value,
      &replacement_data);

  duk_push_heapptr (ctx, replacement_value);
  if (!_gum_duk_get_pointer (ctx, -1, core, &replacement_function))
    _gum_duk_throw (ctx, "expected a pointer");
  duk_pop (ctx);

  entry = g_slice_new (GumDukReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = replacement_value;
  entry->core = core;

  replace_ret = gum_interceptor_replace (self->interceptor, target,
      replacement_function, replacement_data);
  if (replace_ret != GUM_REPLACE_OK)
    goto unable_to_replace;

  _gum_duk_protect (ctx, replacement_value);

  g_hash_table_insert (self->replacement_by_address, target, entry);

  return 0;

unable_to_replace:
  {
    g_slice_free (GumDukReplaceEntry, entry);

    switch (replace_ret)
    {
      case GUM_REPLACE_WRONG_SIGNATURE:
        _gum_duk_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_REPLACE_ALREADY_REPLACED:
        _gum_duk_throw (ctx, "already replaced this function");
      case GUM_REPLACE_POLICY_VIOLATION:
        _gum_duk_throw (ctx, "not permitted by code-signing policy");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_duk_replace_entry_free (GumDukReplaceEntry * entry)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (entry->core);

  gum_interceptor_revert (entry->interceptor, entry->target);

  _gum_duk_unprotect (scope.ctx, entry->replacement);

  g_slice_free (GumDukReplaceEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumDukInterceptor * self;
  gpointer target;

  self = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "p", &target);

  g_hash_table_remove (self->replacement_by_address, target);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  GumDukInterceptor * self;

  self = gumjs_module_from_args (args);

  gum_interceptor_end_transaction (self->interceptor);
  gum_interceptor_begin_transaction (self->interceptor);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_listener_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_listener_detach)
{
  GumDukInterceptor * module;
  GumDukInvocationListener * listener;

  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  listener = _gum_duk_steal_data (ctx, -1);
  if (listener != NULL)
    gum_duk_interceptor_detach (module, listener);
  duk_pop (ctx);

  return 0;
}

static void
gum_duk_invocation_listener_dispose (GumDukInvocationListener * self)
{
  GumDukCore * core = self->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_release_heapptr (ctx, self->object);
  _gum_duk_scope_leave (&scope);
}

static void
gum_duk_js_invocation_listener_on_enter (GumInvocationListener * listener,
                                         GumInvocationContext * ic)
{
  GumDukInvocationListener * self;
  GumDukInvocationState * state;

  self = GUM_DUK_INVOCATION_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumDukInvocationState);

  if (self->on_enter_js != NULL)
  {
    GumDukInterceptor * module = self->module;
    GumDukCore * core = module->core;
    duk_context * ctx;
    GumDukScope scope;
    GumDukInvocationContext * jic;
    GumDukInvocationArgs * args;

    ctx = _gum_duk_scope_enter (&scope, core);

    jic = _gum_duk_interceptor_obtain_invocation_context (module);
    _gum_duk_invocation_context_reset (jic, ic);

    args = gum_duk_interceptor_obtain_invocation_args (module);
    gum_duk_invocation_args_reset (args, ic);

    duk_push_heapptr (ctx, self->on_enter_js);
    duk_push_heapptr (ctx, jic->object);
    duk_push_heapptr (ctx, args->object);
    _gum_duk_scope_call_method (&scope, 1);
    duk_pop (ctx);

    gum_duk_invocation_args_reset (args, NULL);
    gum_duk_interceptor_release_invocation_args (module, args);

    _gum_duk_invocation_context_reset (jic, NULL);
    if (self->on_leave_js != NULL || jic->dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_duk_interceptor_release_invocation_context (module, jic);
      state->jic = NULL;
    }

    _gum_duk_scope_leave (&scope);
  }
  else
  {
    state->jic = NULL;
  }
}

static void
gum_duk_js_invocation_listener_on_leave (GumInvocationListener * listener,
                                         GumInvocationContext * ic)
{
  GumDukInvocationListener * self;
  GumDukInvocationState * state;

  self = GUM_DUK_INVOCATION_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumDukInvocationState);

  if (self->on_leave_js != NULL)
  {
    GumDukInterceptor * module = self->module;
    GumDukCore * core = module->core;
    duk_context * ctx;
    GumDukScope scope;
    GumDukInvocationContext * jic;
    GumDukInvocationReturnValue * retval;

    ctx = _gum_duk_scope_enter (&scope, core);

    jic = (self->on_enter_js != NULL) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_duk_interceptor_obtain_invocation_context (module);
    }
    _gum_duk_invocation_context_reset (jic, ic);

    retval = gum_duk_interceptor_obtain_invocation_return_value (module);
    gum_duk_invocation_return_value_reset (retval, ic);

    duk_push_heapptr (ctx, self->on_leave_js);
    duk_push_heapptr (ctx, jic->object);
    duk_push_heapptr (ctx, retval->object);
    _gum_duk_scope_call_method (&scope, 1);
    duk_pop (ctx);

    gum_duk_invocation_return_value_reset (retval, NULL);
    gum_duk_interceptor_release_invocation_return_value (module, retval);

    _gum_duk_invocation_context_reset (jic, NULL);
    _gum_duk_interceptor_release_invocation_context (module, jic);

    _gum_duk_scope_leave (&scope);
  }
  else if (state->jic != NULL)
  {
    GumDukInterceptor * module = self->module;
    GumDukScope scope;

    _gum_duk_scope_enter (&scope, module->core);

    _gum_duk_interceptor_release_invocation_context (module, state->jic);

    _gum_duk_scope_leave (&scope);
  }
}

static void
gum_duk_c_invocation_listener_on_enter (GumInvocationListener * listener,
                                        GumInvocationContext * ic)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (listener);

  if (self->on_enter_c != NULL)
    self->on_enter_c (ic);
}

static void
gum_duk_c_invocation_listener_on_leave (GumInvocationListener * listener,
                                        GumInvocationContext * ic)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (listener);

  if (self->on_leave_c != NULL)
    self->on_leave_c (ic);
}

static void
gum_duk_js_call_listener_class_init (GumDukJSCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_js_call_listener_dispose;
}

static void
gum_duk_js_call_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_duk_js_invocation_listener_on_enter;
  iface->on_leave = gum_duk_js_invocation_listener_on_leave;
}

static void
gum_duk_js_call_listener_init (GumDukJSCallListener * self)
{
}

static void
gum_duk_js_call_listener_dispose (GObject * object)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (object);

  gum_duk_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_duk_js_call_listener_parent_class)->dispose (object);
}

static void
gum_duk_js_probe_listener_class_init (GumDukJSProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_js_probe_listener_dispose;
}

static void
gum_duk_js_probe_listener_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_duk_js_invocation_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_duk_js_probe_listener_init (GumDukJSProbeListener * self)
{
}

static void
gum_duk_js_probe_listener_dispose (GObject * object)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (object);

  gum_duk_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_duk_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_duk_c_call_listener_class_init (GumDukCCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_c_call_listener_dispose;
}

static void
gum_duk_c_call_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_duk_c_invocation_listener_on_enter;
  iface->on_leave = gum_duk_c_invocation_listener_on_leave;
}

static void
gum_duk_c_call_listener_init (GumDukCCallListener * self)
{
}

static void
gum_duk_c_call_listener_dispose (GObject * object)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (object);

  gum_duk_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_duk_c_call_listener_parent_class)->dispose (object);
}

static void
gum_duk_c_probe_listener_class_init (GumDukCProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_c_probe_listener_dispose;
}

static void
gum_duk_c_probe_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_duk_c_invocation_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_duk_c_probe_listener_init (GumDukCProbeListener * self)
{
}

static void
gum_duk_c_probe_listener_dispose (GObject * object)
{
  GumDukInvocationListener * self = GUM_DUK_INVOCATION_LISTENER_CAST (object);

  gum_duk_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_duk_c_probe_listener_parent_class)->dispose (object);
}

static GumDukInvocationContext *
gum_duk_invocation_context_new (GumDukInterceptor * parent)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (parent->core);
  duk_context * ctx = scope.ctx;
  GumDukInvocationContext * jic;

  jic = g_slice_new (GumDukInvocationContext);

  duk_push_heapptr (ctx, parent->invocation_context);
  duk_new (ctx, 0);

  _gum_duk_put_data (ctx, -1, jic);

  _gum_duk_push_proxy (ctx, -1, NULL, gumjs_invocation_context_set_property);
  jic->object = _gum_duk_require_heapptr (ctx, -1);

  duk_pop_2 (ctx);

  jic->handle = NULL;
  jic->cpu_context = NULL;
  jic->dirty = FALSE;

  jic->interceptor = parent;

  return jic;
}

static void
gum_duk_invocation_context_release (GumDukInvocationContext * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->interceptor->core);

  _gum_duk_release_heapptr (scope.ctx, self->object);
}

void
_gum_duk_invocation_context_reset (GumDukInvocationContext * self,
                                   GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != NULL)
  {
    GumDukScope scope = GUM_DUK_SCOPE_INIT (self->interceptor->core);
    duk_context * ctx = scope.ctx;

    _gum_duk_cpu_context_make_read_only (self->cpu_context);
    self->cpu_context = NULL;

    duk_push_heapptr (ctx, self->object);
    duk_push_null (ctx);
    duk_put_prop_string (ctx, -2, DUK_HIDDEN_SYMBOL ("cc"));
    duk_pop (ctx);
  }
}

static GumDukInvocationContext *
gumjs_invocation_context_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukInvocationContext * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  if (self->handle == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_context_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumDukInvocationContext * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukInvocationContext, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumDukInvocationContext * self = gumjs_invocation_context_from_args (args);

  _gum_duk_push_native_pointer (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumDukInvocationContext * self = gumjs_invocation_context_from_args (args);

  if (self->cpu_context == NULL)
  {
    duk_push_this (ctx);
    self->cpu_context = _gum_duk_push_cpu_context (ctx,
        self->handle->cpu_context, GUM_CPU_CONTEXT_READWRITE, args->core);
    duk_put_prop_string (ctx, -2, DUK_HIDDEN_SYMBOL ("cc"));
    duk_pop (ctx);
  }

  duk_push_heapptr (ctx, self->cpu_context->object);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumDukInvocationContext * self = gumjs_invocation_context_from_args (args);

  duk_push_number (ctx, self->handle->system_error);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  GumDukInvocationContext * self;
  gint value;

  self = gumjs_invocation_context_from_args (args);

  _gum_duk_args_parse (args, "i", &value);

  self->handle->system_error = value;
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumDukInvocationContext * self = gumjs_invocation_context_from_args (args);

  duk_push_number (ctx,
      gum_invocation_context_get_thread_id (self->handle));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumDukInvocationContext * self = gumjs_invocation_context_from_args (args);

  duk_push_number (ctx, gum_invocation_context_get_depth (self->handle));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_property)
{
  GumDukInvocationContext * self;
  GumDukHeapPtr receiver;
  GumDukInterceptor * interceptor;

  self = _gum_duk_require_data (ctx, 0);
  receiver = duk_require_heapptr (ctx, 3);
  interceptor = self->interceptor;

  duk_dup (ctx, 1);
  duk_dup (ctx, 2);
  duk_put_prop (ctx, 0);

  if (receiver == interceptor->cached_invocation_context->object)
  {
    interceptor->cached_invocation_context =
        gum_duk_invocation_context_new (interceptor);
    interceptor->cached_invocation_context_in_use = FALSE;
  }

  self->dirty = TRUE;

  duk_push_true (ctx);
  return 1;
}

static GumDukInvocationArgs *
gum_duk_invocation_args_new (GumDukInterceptor * parent)
{
  GumDukCore * core = parent->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;
  GumDukInvocationArgs * args;

  args = g_slice_new (GumDukInvocationArgs);

  duk_push_heapptr (ctx, parent->invocation_args);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, args);
  args->object = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  args->ic = NULL;
  args->core = core;

  return args;
}

static void
gum_duk_invocation_args_release (GumDukInvocationArgs * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->object);
}

static void
gum_duk_invocation_args_reset (GumDukInvocationArgs * self,
                               GumInvocationContext * ic)
{
  self->ic = ic;
}

static GumInvocationContext *
gumjs_invocation_args_require_context (duk_context * ctx,
                                       duk_idx_t index)
{
  GumDukInvocationArgs * self = _gum_duk_require_data (ctx, index);

  if (self->ic == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  return self->ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_args_construct)
{
  duk_push_this (ctx);
  _gum_duk_push_proxy (ctx, -1, gumjs_invocation_args_get_property,
      gumjs_invocation_args_set_property);
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_args_finalize)
{
  GumDukInvocationArgs * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukInvocationArgs, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  GumInvocationContext * ic;
  guint n;

  if (duk_is_string (ctx, 1) &&
      strcmp (duk_require_string (ctx, 1), "toJSON") == 0)
  {
    duk_push_string (ctx, "invocation-args");
    return 1;
  }

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gum_duk_require_index (ctx, 1);

  _gum_duk_push_native_pointer (ctx,
      gum_invocation_context_get_nth_argument (ic, n), args->core);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_args_set_property)
{
  GumInvocationContext * ic;
  guint n;
  gpointer value;

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gum_duk_require_index (ctx, 1);
  if (!_gum_duk_get_pointer (ctx, 2, args->core, &value))
  {
    duk_push_false (ctx);
    return 1;
  }

  gum_invocation_context_replace_nth_argument (ic, n, value);

  duk_push_true (ctx);
  return 1;
}

static GumDukInvocationReturnValue *
gum_duk_invocation_return_value_new (GumDukInterceptor * parent)
{
  GumDukCore * core = parent->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;
  GumDukInvocationReturnValue * retval;
  GumDukNativePointer * ptr;

  retval = g_slice_new (GumDukInvocationReturnValue);

  ptr = &retval->parent;
  ptr->value = NULL;

  duk_push_heapptr (ctx, parent->invocation_retval);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, retval);
  retval->object = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  retval->ic = NULL;
  retval->core = core;

  return retval;
}

static void
gum_duk_invocation_return_value_release (GumDukInvocationReturnValue * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->object);
}

static void
gum_duk_invocation_return_value_reset (GumDukInvocationReturnValue * self,
                                       GumInvocationContext * ic)
{
  GumDukNativePointer * ptr;

  ptr = &self->parent;
  if (ic != NULL)
    ptr->value = gum_invocation_context_get_return_value (ic);
  else
    ptr->value = NULL;

  self->ic = ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_return_value_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_return_value_finalize)
{
  GumDukInvocationReturnValue * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukInvocationReturnValue, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  GumDukInvocationReturnValue * self;
  GumDukNativePointer * ptr;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  if (self->ic == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  ptr = &self->parent;
  _gum_duk_args_parse (args, "p~", &ptr->value);

  gum_invocation_context_replace_return_value (self->ic, ptr->value);

  return 0;
}

GumDukInvocationContext *
_gum_duk_interceptor_obtain_invocation_context (GumDukInterceptor * self)
{
  GumDukInvocationContext * jic;

  if (!self->cached_invocation_context_in_use)
  {
    jic = self->cached_invocation_context;
    self->cached_invocation_context_in_use = TRUE;
  }
  else
  {
    jic = gum_duk_invocation_context_new (self);
  }

  return jic;
}

void
_gum_duk_interceptor_release_invocation_context (GumDukInterceptor * self,
                                                 GumDukInvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_duk_invocation_context_release (jic);
}

static GumDukInvocationArgs *
gum_duk_interceptor_obtain_invocation_args (GumDukInterceptor * self)
{
  GumDukInvocationArgs * args;

  if (!self->cached_invocation_args_in_use)
  {
    args = self->cached_invocation_args;
    self->cached_invocation_args_in_use = TRUE;
  }
  else
  {
    args = gum_duk_invocation_args_new (self);
  }

  return args;
}

static void
gum_duk_interceptor_release_invocation_args (GumDukInterceptor * self,
                                             GumDukInvocationArgs * args)
{
  if (args == self->cached_invocation_args)
    self->cached_invocation_args_in_use = FALSE;
  else
    gum_duk_invocation_args_release (args);
}

static GumDukInvocationReturnValue *
gum_duk_interceptor_obtain_invocation_return_value (GumDukInterceptor * self)
{
  GumDukInvocationReturnValue * retval;

  if (!self->cached_invocation_return_value_in_use)
  {
    retval = self->cached_invocation_return_value;
    self->cached_invocation_return_value_in_use = TRUE;
  }
  else
  {
    retval = gum_duk_invocation_return_value_new (self);
  }

  return retval;
}

static void
gum_duk_interceptor_release_invocation_return_value (
    GumDukInterceptor * self,
    GumDukInvocationReturnValue * retval)
{
  if (retval == self->cached_invocation_return_value)
    self->cached_invocation_return_value_in_use = FALSE;
  else
    gum_duk_invocation_return_value_release (retval);
}
