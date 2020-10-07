/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinterceptor.h"

#include "gumquickmacros.h"

#define GUM_QUICK_INVOCATION_LISTENER_CAST(obj) \
    ((GumQuickInvocationListener *) (obj))
#define GUM_QUICK_TYPE_JS_CALL_LISTENER (gum_quick_js_call_listener_get_type ())
#define GUM_QUICK_TYPE_JS_PROBE_LISTENER \
    (gum_quick_js_probe_listener_get_type ())
#define GUM_QUICK_TYPE_C_CALL_LISTENER (gum_quick_c_call_listener_get_type ())
#define GUM_QUICK_TYPE_C_PROBE_LISTENER (gum_quick_c_probe_listener_get_type ())

typedef struct _GumQuickInvocationListener GumQuickInvocationListener;
typedef struct _GumQuickJSCallListener GumQuickJSCallListener;
typedef struct _GumQuickJSCallListenerClass GumQuickJSCallListenerClass;
typedef struct _GumQuickJSProbeListener GumQuickJSProbeListener;
typedef struct _GumQuickJSProbeListenerClass GumQuickJSProbeListenerClass;
typedef struct _GumQuickCCallListener GumQuickCCallListener;
typedef struct _GumQuickCCallListenerClass GumQuickCCallListenerClass;
typedef struct _GumQuickCProbeListener GumQuickCProbeListener;
typedef struct _GumQuickCProbeListenerClass GumQuickCProbeListenerClass;
typedef struct _GumQuickInvocationState GumQuickInvocationState;
typedef struct _GumQuickReplaceEntry GumQuickReplaceEntry;

struct _GumQuickInvocationListener
{
  GObject parent;

  JSValue object;
  union
  {
    gpointer on_enter;
    JSValue on_enter_js;
    void (* on_enter_c) (GumInvocationContext * ic);
  };
  union
  {
    gpointer on_leave;
    JSValue on_leave_js;
    void (* on_leave_c) (GumInvocationContext * ic);
  };

  GumQuickInterceptor * module;
};

struct _GumQuickJSCallListener
{
  GumQuickInvocationListener listener;
};

struct _GumQuickJSCallListenerClass
{
  GObjectClass parent_class;
};

struct _GumQuickJSProbeListener
{
  GumQuickInvocationListener listener;
};

struct _GumQuickJSProbeListenerClass
{
  GObjectClass parent_class;
};

struct _GumQuickCCallListener
{
  GumQuickInvocationListener listener;
};

struct _GumQuickCCallListenerClass
{
  GObjectClass parent_class;
};

struct _GumQuickCProbeListener
{
  GumQuickInvocationListener listener;
};

struct _GumQuickCProbeListenerClass
{
  GObjectClass parent_class;
};

struct _GumQuickInvocationState
{
  GumQuickInvocationContext * jic;
};

struct _GumQuickInvocationArgs
{
  JSValue object;
  GumInvocationContext * ic;

  GumQuickCore * core;
};

struct _GumQuickInvocationRetval
{
  GumQuickNativePointer parent;

  JSValue object;
  GumInvocationContext * ic;

  GumQuickCore * core;
};

struct _GumQuickReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  JSValue replacement;
  GumQuickCore * core;
};

static gboolean gum_quick_interceptor_on_flush_timer_tick (
    GumQuickInterceptor * self);

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_quick_invocation_listener_destroy (
    GumQuickInvocationListener * listener);
static void gum_quick_interceptor_detach (GumQuickInterceptor * self,
    GumQuickInvocationListener * listener);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_quick_replace_entry_free (GumQuickReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_listener_construct)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)

static void gum_quick_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_call_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickJSCallListener,
                        gum_quick_js_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_call_listener_iface_init))

static void gum_quick_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_probe_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickJSProbeListener,
                        gum_quick_js_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_probe_listener_iface_init))

static void gum_quick_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_call_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickCCallListener,
                        gum_quick_c_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_call_listener_iface_init))

static void gum_quick_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_probe_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickCProbeListener,
                        gum_quick_c_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_probe_listener_iface_init))

static GumQuickInvocationContext * gum_quick_invocation_context_new (
    GumQuickInterceptor * parent);
static void gum_quick_invocation_context_release (GumQuickInvocationContext * self);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_property)

static GumQuickInvocationArgs * gum_quick_invocation_args_new (
    GumQuickInterceptor * parent);
static void gum_quick_invocation_args_release (GumQuickInvocationArgs * self);
static void gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
    GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_args_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_args_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static GumQuickInvocationRetval * gum_quick_invocation_retval_new (
    GumQuickInterceptor * parent);
static void gum_quick_invocation_retval_release (
    GumQuickInvocationRetval * self);
static void gum_quick_invocation_retval_reset (
    GumQuickInvocationRetval * self, GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_retval_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_retval_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_retval_replace)

static GumQuickInvocationArgs * gum_quick_interceptor_obtain_invocation_args (
    GumQuickInterceptor * self);
static void gum_quick_interceptor_release_invocation_args (
    GumQuickInterceptor * self, GumQuickInvocationArgs * args);
static GumQuickInvocationRetval *
gum_quick_interceptor_obtain_invocation_retval (GumQuickInterceptor * self);
static void gum_quick_interceptor_release_invocation_retval (
    GumQuickInterceptor * self, GumQuickInvocationRetval * retval);

static const JSCFunctionListEntry gumjs_interceptor_entries[] =
{
  JS_CFUNC_DEF ("_attach", 3, gumjs_interceptor_attach),
  JS_CFUNC_DEF ("detachAll", 0, gumjs_interceptor_detach_all),
  JS_CFUNC_DEF ("_replace", 3, gumjs_interceptor_replace),
  JS_CFUNC_DEF ("revert", 1, gumjs_interceptor_revert),
  JS_CFUNC_DEF ("flush", 0, gumjs_interceptor_flush),
};

static const JSClassDef gumjs_invocation_listener_def =
{
  "InvocationListener",
};

static const JSCFunctionListEntry gumjs_invocation_listener_entries[] =
{
  JS_CFUNC_DEF ("detach", 0, gumjs_invocation_listener_detach),
};

static const JSClassDef gumjs_invocation_context_def =
{
  "InvocationContext",
  gumjs_invocation_context_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_context_entries[] =
{
  JS_CGETSET_DEF (
      "returnAddress",
      gumjs_invocation_context_get_return_address,
      NULL),
  JS_CGETSET_DEF (
      "context",
      gumjs_invocation_context_get_cpu_context,
      NULL),
  JS_CGETSET_DEF (
      GUMJS_SYSTEM_ERROR_FIELD,
      gumjs_invocation_context_get_system_error,
      gumjs_invocation_context_set_system_error),
  JS_CGETSET_DEF (
      "threadId",
      gumjs_invocation_context_get_thread_id,
      NULL),
  JS_CGETSET_DEF (
      "depth",
      gumjs_invocation_context_get_depth,
      NULL),
};

static const JSClassDef gumjs_invocation_args_def =
{
  "InvocationArgs",
  gumjs_invocation_args_finalize,
};

static const JSClassDef gumjs_invocation_retval_def =
{
  "InvocationReturnValue",
  gumjs_invocation_retval_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_retval_entries[] =
{
  JS_CFUNC_DEF ("replace", 1, gumjs_invocation_retval_replace),
};

void
_gum_quick_interceptor_init (GumQuickInterceptor * self,
                             JSValue ns,
                             GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSRuntime * rt;
  JSValue obj, proto, ctor;

  rt = JS_GetRuntime (ctx);

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_invocation_listener_destroy);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_replace_entry_free);
  self->flush_timer = NULL;

  _gum_quick_store_module_data (ctx, "interceptor", self);

  obj = JS_NewObject (ctx);
  JS_DefinePropertyValueStr (ctx, ns, "Interceptor", obj, JS_PROP_C_W_E);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_interceptor_entries,
      G_N_ELEMENTS (gumjs_interceptor_entries));

  JS_NewClassID (&self->invocation_listener_class);
  JS_NewClass (rt, self->invocation_listener_class,
      &gumjs_invocation_listener_def);
  proto = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_listener_entries,
      G_N_ELEMENTS (gumjs_invocation_listener_entries));
  ctor = JS_NewCFunction2 (ctx, gumjs_invocation_listener_construct,
      gumjs_invocation_listener_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->invocation_listener_class, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_invocation_listener_def.class_name,
      ctor, JS_PROP_C_W_E);

  JS_NewClassID (&self->invocation_context_class);
  JS_NewClass (rt, self->invocation_context_class,
      &gumjs_invocation_context_def);
  proto = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_context_entries,
      G_N_ELEMENTS (gumjs_invocation_context_entries));
  ctor = JS_NewCFunction2 (ctx, gumjs_invocation_context_construct,
      gumjs_invocation_context_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->invocation_context_class, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_invocation_context_def.class_name,
      ctor, JS_PROP_C_W_E);

  JS_NewClassID (&self->invocation_args_class);
  JS_NewClass (rt, self->invocation_args_class, &gumjs_invocation_args_def);
  proto = JS_NewObject (ctx);
  ctor = JS_NewCFunction2 (ctx, gumjs_invocation_args_construct,
      gumjs_invocation_args_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->invocation_args_class, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_invocation_args_def.class_name,
      ctor, JS_PROP_C_W_E);

  JS_NewClassID (&self->invocation_retval_class);
  JS_NewClass (rt, self->invocation_retval_class,
      &gumjs_invocation_retval_def);
  proto = JS_NewObjectProto (ctx, core->native_pointer_proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_retval_entries,
      G_N_ELEMENTS (gumjs_invocation_retval_entries));
  ctor = JS_NewCFunction2 (ctx, gumjs_invocation_retval_construct,
      gumjs_invocation_retval_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->invocation_retval_class, proto);
  JS_DefinePropertyValueStr (ctx, ns,
      gumjs_invocation_retval_def.class_name, ctor, JS_PROP_C_W_E);

  self->cached_invocation_context = gum_quick_invocation_context_new (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args = gum_quick_invocation_args_new (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_retval = gum_quick_invocation_retval_new (
      self);
  self->cached_invocation_retval_in_use = FALSE;
}

void
_gum_quick_interceptor_flush (GumQuickInterceptor * self)
{
  GumQuickCore * core = self->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  _gum_quick_scope_suspend (&scope);

  flushed = gum_interceptor_flush (self->interceptor);

  _gum_quick_scope_resume (&scope);

  if (!flushed && self->flush_timer == NULL)
  {
    GSource * source;

    source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_quick_interceptor_on_flush_timer_tick, self, NULL);
    self->flush_timer = source;

    _gum_quick_core_pin (core);
    _gum_quick_scope_suspend (&scope);

    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);

    _gum_quick_scope_resume (&scope);
  }
}

static gboolean
gum_quick_interceptor_on_flush_timer_tick (GumQuickInterceptor * self)
{
  gboolean flushed;

  flushed = gum_interceptor_flush (self->interceptor);
  if (flushed)
  {
    GumQuickCore * core = self->core;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);
    _gum_quick_core_unpin (core);
    self->flush_timer = NULL;
    _gum_quick_scope_leave (&scope);
  }

  return !flushed;
}

void
_gum_quick_interceptor_dispose (GumQuickInterceptor * self)
{
  g_assert (self->flush_timer == NULL);

  gum_quick_invocation_context_release (self->cached_invocation_context);
  gum_quick_invocation_args_release (self->cached_invocation_args);
  gum_quick_invocation_retval_release (self->cached_invocation_retval);
}

void
_gum_quick_interceptor_finalize (GumQuickInterceptor * self)
{
  g_clear_pointer (&self->invocation_listeners, g_hash_table_unref);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

static GumQuickInterceptor *
gumjs_module_from_args (const GumQuickArgs * args)
{
  return _gum_quick_load_module_data (args->ctx, "interceptor");
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  JSValueConst target_val = args->elements[0];
  JSValueConst cb_val = args->elements[1];
  GumQuickInterceptor * self;
  GumQuickCore * core = args->core;
  gpointer target, on_enter, on_leave;
  GumQuickInvocationListener * listener;
  gpointer listener_function_data;
  GumAttachReturn attach_ret;

  self = gumjs_module_from_args (args);

  quick_push_heapptr (ctx, core->native_pointer);

  if (JS_IsFunction (ctx, cb_val))
  {
    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      return JS_EXCEPTION;
    on_enter = quick_require_heapptr (ctx, 1);
    on_leave = NULL;

    listener = g_object_new (GUM_QUICK_TYPE_JS_PROBE_LISTENER, NULL);
  }
  else if (_gum_quick_native_pointer_try_get (ctx, cb_val, core, &on_enter))
  {
    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      return JS_EXCEPTION;
    on_leave = NULL;

    listener = g_object_new (GUM_QUICK_TYPE_C_PROBE_LISTENER, NULL);
  }
  else
  {
    gpointer on_enter_js, on_enter_c;
    gpointer on_leave_js, on_leave_c;

    _gum_quick_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c);

    if (on_enter_js != NULL || on_leave_js != NULL)
    {
      on_enter = on_enter_js;
      on_leave = on_leave_js;

      listener = g_object_new (GUM_QUICK_TYPE_JS_CALL_LISTENER, NULL);
    }
    else
    {
      on_enter = on_enter_c;
      on_leave = on_leave_c;

      listener = g_object_new (GUM_QUICK_TYPE_C_CALL_LISTENER, NULL);
    }
  }

  quick_pop (ctx);

  if (!quick_is_undefined (ctx, 2))
    listener_function_data = _gum_quick_require_pointer (ctx, 2, core);
  else
    listener_function_data = NULL;

  listener->on_enter = on_enter;
  listener->on_leave = on_leave;
  listener->module = self;

  attach_ret = gum_interceptor_attach (self->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  quick_push_heapptr (ctx, self->invocation_listener);
  quick_new (ctx, 0);

  listener->object = _gum_quick_require_heapptr (ctx, -1);

  _gum_quick_put_data (ctx, -1, listener);

  quick_dup (ctx, 1);
  quick_put_prop_string (ctx, -2, QUICK_HIDDEN_SYMBOL ("resource"));

  g_hash_table_add (self->invocation_listeners, listener);

  return 1;

unable_to_attach:
  {
    g_object_unref (listener);

    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gum_quick_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gum_quick_throw (ctx, "already attached to this function");
      case GUM_ATTACH_POLICY_VIOLATION:
        _gum_quick_throw (ctx, "not permitted by code-signing policy");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_quick_invocation_listener_destroy (GumQuickInvocationListener * listener)
{
  gum_interceptor_detach (listener->module->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_quick_interceptor_detach (GumQuickInterceptor * self,
                            GumQuickInvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumQuickInterceptor * self = gumjs_module_from_args (args);

  g_hash_table_remove_all (self->invocation_listeners);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumQuickInterceptor * self;
  GumQuickCore * core = args->core;
  gpointer target, replacement_function, replacement_data;
  JSValue replacement_value;
  GumQuickReplaceEntry * entry;
  GumReplaceReturn replace_ret;

  self = gumjs_module_from_args (args);

  replacement_data = NULL;
  _gum_quick_args_parse (args, "pO|p", &target, &replacement_value,
      &replacement_data);

  quick_push_heapptr (ctx, replacement_value);
  if (!_gum_quick_get_pointer (ctx, -1, core, &replacement_function))
    _gum_quick_throw (ctx, "expected a pointer");
  quick_pop (ctx);

  entry = g_slice_new (GumQuickReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = replacement_value;
  entry->core = core;

  replace_ret = gum_interceptor_replace (self->interceptor, target,
      replacement_function, replacement_data);
  if (replace_ret != GUM_REPLACE_OK)
    goto unable_to_replace;

  _gum_quick_protect (ctx, replacement_value);

  g_hash_table_insert (self->replacement_by_address, target, entry);

  return 0;

unable_to_replace:
  {
    g_slice_free (GumQuickReplaceEntry, entry);

    switch (replace_ret)
    {
      case GUM_REPLACE_WRONG_SIGNATURE:
        _gum_quick_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_REPLACE_ALREADY_REPLACED:
        _gum_quick_throw (ctx, "already replaced this function");
      case GUM_REPLACE_POLICY_VIOLATION:
        _gum_quick_throw (ctx, "not permitted by code-signing policy");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_quick_replace_entry_free (GumQuickReplaceEntry * entry)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (entry->core);

  gum_interceptor_revert (entry->interceptor, entry->target);

  _gum_quick_unprotect (scope.ctx, entry->replacement);

  g_slice_free (GumQuickReplaceEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumQuickInterceptor * self;
  gpointer target;

  self = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "p", &target);

  g_hash_table_remove (self->replacement_by_address, target);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  GumQuickInterceptor * self;

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
  GumQuickInterceptor * module;
  GumQuickInvocationListener * listener;

  module = gumjs_module_from_args (args);

  quick_push_this (ctx);
  listener = _gum_quick_steal_data (ctx, -1);
  if (listener != NULL)
    gum_quick_interceptor_detach (module, listener);
  quick_pop (ctx);

  return 0;
}

static void
gum_quick_invocation_listener_dispose (GumQuickInvocationListener * self)
{
  GumQuickCore * core = self->module->core;
  GumQuickScope scope;
  JSContext * ctx;

  ctx = _gum_quick_scope_enter (&scope, core);
  _gum_quick_release_heapptr (ctx, self->object);
  _gum_quick_scope_leave (&scope);
}

static void
gum_quick_js_invocation_listener_on_enter (GumInvocationListener * listener,
                                         GumInvocationContext * ic)
{
  GumQuickInvocationListener * self;
  GumQuickInvocationState * state;

  self = GUM_QUICK_INVOCATION_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (self->on_enter_js != NULL)
  {
    GumQuickInterceptor * module = self->module;
    GumQuickCore * core = module->core;
    JSContext * ctx;
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationArgs * args;

    ctx = _gum_quick_scope_enter (&scope, core);

    jic = _gum_quick_interceptor_obtain_invocation_context (module);
    _gum_quick_invocation_context_reset (jic, ic);

    args = gum_quick_interceptor_obtain_invocation_args (module);
    gum_quick_invocation_args_reset (args, ic);

    quick_push_heapptr (ctx, self->on_enter_js);
    quick_push_heapptr (ctx, jic->object);
    quick_push_heapptr (ctx, args->object);
    _gum_quick_scope_call_method (&scope, 1);
    quick_pop (ctx);

    gum_quick_invocation_args_reset (args, NULL);
    gum_quick_interceptor_release_invocation_args (module, args);

    _gum_quick_invocation_context_reset (jic, NULL);
    if (self->on_leave_js != NULL || jic->dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_quick_interceptor_release_invocation_context (module, jic);
      state->jic = NULL;
    }

    _gum_quick_scope_leave (&scope);
  }
  else
  {
    state->jic = NULL;
  }
}

static void
gum_quick_js_invocation_listener_on_leave (GumInvocationListener * listener,
                                         GumInvocationContext * ic)
{
  GumQuickInvocationListener * self;
  GumQuickInvocationState * state;

  self = GUM_QUICK_INVOCATION_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (self->on_leave_js != NULL)
  {
    GumQuickInterceptor * module = self->module;
    GumQuickCore * core = module->core;
    JSContext * ctx;
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationRetval * retval;

    ctx = _gum_quick_scope_enter (&scope, core);

    jic = (self->on_enter_js != NULL) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_quick_interceptor_obtain_invocation_context (module);
    }
    _gum_quick_invocation_context_reset (jic, ic);

    retval = gum_quick_interceptor_obtain_invocation_retval (module);
    gum_quick_invocation_retval_reset (retval, ic);

    quick_push_heapptr (ctx, self->on_leave_js);
    quick_push_heapptr (ctx, jic->object);
    quick_push_heapptr (ctx, retval->object);
    _gum_quick_scope_call_method (&scope, 1);
    quick_pop (ctx);

    gum_quick_invocation_retval_reset (retval, NULL);
    gum_quick_interceptor_release_invocation_retval (module, retval);

    _gum_quick_invocation_context_reset (jic, NULL);
    _gum_quick_interceptor_release_invocation_context (module, jic);

    _gum_quick_scope_leave (&scope);
  }
  else if (state->jic != NULL)
  {
    GumQuickInterceptor * module = self->module;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, module->core);

    _gum_quick_interceptor_release_invocation_context (module, state->jic);

    _gum_quick_scope_leave (&scope);
  }
}

static void
gum_quick_c_invocation_listener_on_enter (GumInvocationListener * listener,
                                        GumInvocationContext * ic)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (listener);

  if (self->on_enter_c != NULL)
    self->on_enter_c (ic);
}

static void
gum_quick_c_invocation_listener_on_leave (GumInvocationListener * listener,
                                        GumInvocationContext * ic)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (listener);

  if (self->on_leave_c != NULL)
    self->on_leave_c (ic);
}

static void
gum_quick_js_call_listener_class_init (GumQuickJSCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_js_call_listener_dispose;
}

static void
gum_quick_js_call_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_js_invocation_listener_on_enter;
  iface->on_leave = gum_quick_js_invocation_listener_on_leave;
}

static void
gum_quick_js_call_listener_init (GumQuickJSCallListener * self)
{
}

static void
gum_quick_js_call_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (object);

  gum_quick_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_quick_js_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_js_probe_listener_class_init (GumQuickJSProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_js_probe_listener_dispose;
}

static void
gum_quick_js_probe_listener_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_js_invocation_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_js_probe_listener_init (GumQuickJSProbeListener * self)
{
}

static void
gum_quick_js_probe_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (object);

  gum_quick_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_quick_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_call_listener_class_init (GumQuickCCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_c_call_listener_dispose;
}

static void
gum_quick_c_call_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_c_invocation_listener_on_enter;
  iface->on_leave = gum_quick_c_invocation_listener_on_leave;
}

static void
gum_quick_c_call_listener_init (GumQuickCCallListener * self)
{
}

static void
gum_quick_c_call_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (object);

  gum_quick_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_quick_c_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_probe_listener_class_init (GumQuickCProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_c_probe_listener_dispose;
}

static void
gum_quick_c_probe_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_c_invocation_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_c_probe_listener_init (GumQuickCProbeListener * self)
{
}

static void
gum_quick_c_probe_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * self = GUM_QUICK_INVOCATION_LISTENER_CAST (object);

  gum_quick_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_quick_c_probe_listener_parent_class)->dispose (object);
}

static GumQuickInvocationContext *
gum_quick_invocation_context_new (GumQuickInterceptor * parent)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (parent->core);
  JSContext * ctx = scope.ctx;
  GumQuickInvocationContext * jic;

  jic = g_slice_new (GumQuickInvocationContext);

  quick_push_heapptr (ctx, parent->invocation_context);
  quick_new (ctx, 0);

  _gum_quick_put_data (ctx, -1, jic);

  _gum_quick_push_proxy (ctx, -1, NULL, gumjs_invocation_context_set_property);
  jic->object = _gum_quick_require_heapptr (ctx, -1);

  quick_pop_2 (ctx);

  jic->handle = NULL;
  jic->cpu_context = NULL;
  jic->dirty = FALSE;

  jic->interceptor = parent;

  return jic;
}

static void
gum_quick_invocation_context_release (GumQuickInvocationContext * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->interceptor->core);

  _gum_quick_release_heapptr (scope.ctx, self->object);
}

void
_gum_quick_invocation_context_reset (GumQuickInvocationContext * self,
                                   GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != NULL)
  {
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->interceptor->core);
    JSContext * ctx = scope.ctx;

    _gum_quick_cpu_context_make_read_only (self->cpu_context);
    self->cpu_context = NULL;

    quick_push_heapptr (ctx, self->object);
    quick_push_null (ctx);
    quick_put_prop_string (ctx, -2, QUICK_HIDDEN_SYMBOL ("cc"));
    quick_pop (ctx);
  }
}

static GumQuickInvocationContext *
gumjs_invocation_context_from_args (const GumQuickArgs * args)
{
  JSContext * ctx = args->ctx;
  GumQuickInvocationContext * self;

  quick_push_this (ctx);
  self = _gum_quick_require_data (ctx, -1);
  quick_pop (ctx);

  if (self->handle == NULL)
    _gum_quick_throw (ctx, "invalid operation");

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_context_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumQuickInvocationContext * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumQuickInvocationContext, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumQuickInvocationContext * self = gumjs_invocation_context_from_args (args);

  _gum_quick_push_native_pointer (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumQuickInvocationContext * self = gumjs_invocation_context_from_args (args);

  if (self->cpu_context == NULL)
  {
    quick_push_this (ctx);
    self->cpu_context = _gum_quick_push_cpu_context (ctx,
        self->handle->cpu_context, GUM_CPU_CONTEXT_READWRITE, args->core);
    quick_put_prop_string (ctx, -2, QUICK_HIDDEN_SYMBOL ("cc"));
    quick_pop (ctx);
  }

  quick_push_heapptr (ctx, self->cpu_context->object);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumQuickInvocationContext * self = gumjs_invocation_context_from_args (args);

  quick_push_number (ctx, self->handle->system_error);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  GumQuickInvocationContext * self;
  gint value;

  self = gumjs_invocation_context_from_args (args);

  _gum_quick_args_parse (args, "i", &value);

  self->handle->system_error = value;
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumQuickInvocationContext * self = gumjs_invocation_context_from_args (args);

  quick_push_number (ctx,
      gum_invocation_context_get_thread_id (self->handle));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumQuickInvocationContext * self = gumjs_invocation_context_from_args (args);

  quick_push_number (ctx, gum_invocation_context_get_depth (self->handle));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_property)
{
  GumQuickInvocationContext * self;
  JSValue receiver;
  GumQuickInterceptor * interceptor;

  self = _gum_quick_require_data (ctx, 0);
  receiver = quick_require_heapptr (ctx, 3);
  interceptor = self->interceptor;

  quick_dup (ctx, 1);
  quick_dup (ctx, 2);
  quick_put_prop (ctx, 0);

  if (receiver == interceptor->cached_invocation_context->object)
  {
    interceptor->cached_invocation_context =
        gum_quick_invocation_context_new (interceptor);
    interceptor->cached_invocation_context_in_use = FALSE;
  }

  self->dirty = TRUE;

  quick_push_true (ctx);
  return 1;
}

static GumQuickInvocationArgs *
gum_quick_invocation_args_new (GumQuickInterceptor * parent)
{
  GumQuickCore * core = parent->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  JSContext * ctx = scope.ctx;
  GumQuickInvocationArgs * args;

  args = g_slice_new (GumQuickInvocationArgs);

  quick_push_heapptr (ctx, parent->invocation_args);
  quick_new (ctx, 0);
  _gum_quick_put_data (ctx, -1, args);
  args->object = _gum_quick_require_heapptr (ctx, -1);
  quick_pop (ctx);

  args->ic = NULL;
  args->core = core;

  return args;
}

static void
gum_quick_invocation_args_release (GumQuickInvocationArgs * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->core);

  _gum_quick_release_heapptr (scope.ctx, self->object);
}

static void
gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
                               GumInvocationContext * ic)
{
  self->ic = ic;
}

static GumInvocationContext *
gumjs_invocation_args_require_context (JSContext * ctx,
                                       quick_idx_t index)
{
  GumQuickInvocationArgs * self = _gum_quick_require_data (ctx, index);

  if (self->ic == NULL)
    _gum_quick_throw (ctx, "invalid operation");

  return self->ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_args_construct)
{
  quick_push_this (ctx);
  _gum_quick_push_proxy (ctx, -1, gumjs_invocation_args_get_property,
      gumjs_invocation_args_set_property);
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_args_finalize)
{
  GumQuickInvocationArgs * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumQuickInvocationArgs, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  GumInvocationContext * ic;
  guint n;

  if (quick_is_string (ctx, 1) &&
      strcmp (quick_require_string (ctx, 1), "toJSON") == 0)
  {
    quick_push_string (ctx, "invocation-args");
    return 1;
  }

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gum_quick_require_index (ctx, 1);

  _gum_quick_push_native_pointer (ctx,
      gum_invocation_context_get_nth_argument (ic, n), args->core);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_args_set_property)
{
  GumInvocationContext * ic;
  guint n;
  gpointer value;

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gum_quick_require_index (ctx, 1);
  if (!_gum_quick_get_pointer (ctx, 2, args->core, &value))
  {
    quick_push_false (ctx);
    return 1;
  }

  gum_invocation_context_replace_nth_argument (ic, n, value);

  quick_push_true (ctx);
  return 1;
}

static GumQuickInvocationRetval *
gum_quick_invocation_retval_new (GumQuickInterceptor * parent)
{
  GumQuickCore * core = parent->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  JSContext * ctx = scope.ctx;
  GumQuickInvocationRetval * retval;
  GumQuickNativePointer * ptr;

  retval = g_slice_new (GumQuickInvocationRetval);

  ptr = &retval->parent;
  ptr->value = NULL;

  quick_push_heapptr (ctx, parent->invocation_retval);
  quick_new (ctx, 0);
  _gum_quick_put_data (ctx, -1, retval);
  retval->object = _gum_quick_require_heapptr (ctx, -1);
  quick_pop (ctx);

  retval->ic = NULL;
  retval->core = core;

  return retval;
}

static void
gum_quick_invocation_retval_release (GumQuickInvocationRetval * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->core);

  _gum_quick_release_heapptr (scope.ctx, self->object);
}

static void
gum_quick_invocation_retval_reset (GumQuickInvocationRetval * self,
                                       GumInvocationContext * ic)
{
  GumQuickNativePointer * ptr;

  ptr = &self->parent;
  if (ic != NULL)
    ptr->value = gum_invocation_context_get_return_value (ic);
  else
    ptr->value = NULL;

  self->ic = ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_retval_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_retval_finalize)
{
  GumQuickInvocationRetval * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumQuickInvocationRetval, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_retval_replace)
{
  GumQuickInvocationRetval * self;
  GumQuickNativePointer * ptr;

  quick_push_this (ctx);
  self = _gum_quick_require_data (ctx, -1);
  quick_pop (ctx);

  if (self->ic == NULL)
    _gum_quick_throw (ctx, "invalid operation");

  ptr = &self->parent;
  _gum_quick_args_parse (args, "p~", &ptr->value);

  gum_invocation_context_replace_return_value (self->ic, ptr->value);

  return 0;
}

GumQuickInvocationContext *
_gum_quick_interceptor_obtain_invocation_context (GumQuickInterceptor * self)
{
  GumQuickInvocationContext * jic;

  if (!self->cached_invocation_context_in_use)
  {
    jic = self->cached_invocation_context;
    self->cached_invocation_context_in_use = TRUE;
  }
  else
  {
    jic = gum_quick_invocation_context_new (self);
  }

  return jic;
}

void
_gum_quick_interceptor_release_invocation_context (GumQuickInterceptor * self,
                                                 GumQuickInvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_quick_invocation_context_release (jic);
}

static GumQuickInvocationArgs *
gum_quick_interceptor_obtain_invocation_args (GumQuickInterceptor * self)
{
  GumQuickInvocationArgs * args;

  if (!self->cached_invocation_args_in_use)
  {
    args = self->cached_invocation_args;
    self->cached_invocation_args_in_use = TRUE;
  }
  else
  {
    args = gum_quick_invocation_args_new (self);
  }

  return args;
}

static void
gum_quick_interceptor_release_invocation_args (GumQuickInterceptor * self,
                                             GumQuickInvocationArgs * args)
{
  if (args == self->cached_invocation_args)
    self->cached_invocation_args_in_use = FALSE;
  else
    gum_quick_invocation_args_release (args);
}

static GumQuickInvocationRetval *
gum_quick_interceptor_obtain_invocation_retval (GumQuickInterceptor * self)
{
  GumQuickInvocationRetval * retval;

  if (!self->cached_invocation_retval_in_use)
  {
    retval = self->cached_invocation_retval;
    self->cached_invocation_retval_in_use = TRUE;
  }
  else
  {
    retval = gum_quick_invocation_retval_new (self);
  }

  return retval;
}

static void
gum_quick_interceptor_release_invocation_retval (
    GumQuickInterceptor * self,
    GumQuickInvocationRetval * retval)
{
  if (retval == self->cached_invocation_retval)
    self->cached_invocation_retval_in_use = FALSE;
  else
    gum_quick_invocation_retval_release (retval);
}
