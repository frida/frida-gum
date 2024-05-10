/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinterceptor.h"

#include "gumquickmacros.h"

#define GUM_QUICK_TYPE_INVOCATION_LISTENER \
    (gum_quick_invocation_listener_get_type ())
#define GUM_QUICK_TYPE_JS_CALL_LISTENER \
    (gum_quick_js_call_listener_get_type ())
#define GUM_QUICK_TYPE_JS_PROBE_LISTENER \
    (gum_quick_js_probe_listener_get_type ())
#define GUM_QUICK_TYPE_C_CALL_LISTENER \
    (gum_quick_c_call_listener_get_type ())
#define GUM_QUICK_TYPE_C_PROBE_LISTENER \
    (gum_quick_c_probe_listener_get_type ())

#define GUM_QUICK_INVOCATION_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_INVOCATION_LISTENER, \
        GumQuickInvocationListener)
#define GUM_QUICK_JS_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_JS_CALL_LISTENER, \
        GumQuickJSCallListener)
#define GUM_QUICK_JS_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_JS_PROBE_LISTENER, \
        GumQuickJSProbeListener)
#define GUM_QUICK_C_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_C_CALL_LISTENER, \
        GumQuickCCallListener)
#define GUM_QUICK_C_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_C_PROBE_LISTENER, \
        GumQuickCProbeListener)

#define GUM_QUICK_INVOCATION_LISTENER_CAST(obj) \
    ((GumQuickInvocationListener *) (obj))
#define GUM_QUICK_JS_CALL_LISTENER_CAST(obj) \
    ((GumQuickJSCallListener *) (obj))
#define GUM_QUICK_JS_PROBE_LISTENER_CAST(obj) \
    ((GumQuickJSProbeListener *) (obj))
#define GUM_QUICK_C_CALL_LISTENER_CAST(obj) \
    ((GumQuickCCallListener *) (obj))
#define GUM_QUICK_C_PROBE_LISTENER_CAST(obj) \
    ((GumQuickCProbeListener *) (obj))

typedef struct _GumQuickInvocationListener GumQuickInvocationListener;
typedef struct _GumQuickInvocationListenerClass GumQuickInvocationListenerClass;
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

typedef void (* GumQuickCHook) (GumInvocationContext * ic);

struct _GumQuickInvocationListener
{
  GObject object;

  JSValue wrapper;

  GumQuickInterceptor * parent;
};

struct _GumQuickInvocationListenerClass
{
  GObjectClass object_class;
};

struct _GumQuickJSCallListener
{
  GumQuickInvocationListener listener;

  JSValue on_enter;
  JSValue on_leave;
};

struct _GumQuickJSCallListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickJSProbeListener
{
  GumQuickInvocationListener listener;

  JSValue on_hit;
};

struct _GumQuickJSProbeListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickCCallListener
{
  GumQuickInvocationListener listener;

  GumQuickCHook on_enter;
  GumQuickCHook on_leave;
};

struct _GumQuickCCallListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickCProbeListener
{
  GumQuickInvocationListener listener;

  GumQuickCHook on_hit;
};

struct _GumQuickCProbeListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickInvocationState
{
  GumQuickInvocationContext * jic;
};

struct _GumQuickInvocationArgs
{
  JSValue wrapper;
  GumInvocationContext * ic;
  JSContext * ctx;
};

struct _GumQuickInvocationRetval
{
  GumQuickNativePointer native_pointer;

  JSValue wrapper;
  GumInvocationContext * ic;
  JSContext * ctx;
};

struct _GumQuickReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  JSValue replacement;
  JSContext * ctx;
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
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace_fast)
static void gum_quick_add_replace_entry (GumQuickInterceptor * self,
    gpointer target, JSValue replacement_value);
static JSValue gum_quick_handle_replace_ret (JSContext * ctx, gpointer target,
    GumReplaceReturn replace_ret);
static void gum_quick_replace_entry_revert_and_free (
    GumQuickReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)
static void gum_quick_invocation_listener_dispose (GObject * object);
static void gum_quick_invocation_listener_release_wrapper (
    GumQuickInvocationListener * self, JSContext * ctx);
G_DEFINE_TYPE_EXTENDED (GumQuickInvocationListener,
                        gum_quick_invocation_listener,
                        G_TYPE_OBJECT,
                        G_TYPE_FLAG_ABSTRACT,
                        {})

static void gum_quick_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_call_listener_dispose (GObject * object);
static void gum_quick_js_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_quick_js_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickJSCallListener,
                        gum_quick_js_call_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_call_listener_iface_init))

static void gum_quick_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_probe_listener_dispose (GObject * object);
static void gum_quick_js_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickJSProbeListener,
                        gum_quick_js_probe_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_probe_listener_iface_init))

static void gum_quick_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_call_listener_dispose (GObject * object);
static void gum_quick_c_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_quick_c_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickCCallListener,
                        gum_quick_c_call_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_call_listener_iface_init))

static void gum_quick_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_probe_listener_dispose (GObject * object);
static void gum_quick_c_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickCProbeListener,
                        gum_quick_c_probe_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_probe_listener_iface_init))

static JSValue gum_quick_invocation_context_new (GumQuickInterceptor * parent,
    GumQuickInvocationContext ** context);
static void gum_quick_invocation_context_release (
    GumQuickInvocationContext * self);
static gboolean gum_quick_invocation_context_is_dirty (
    GumQuickInvocationContext * self);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)

static JSValue gum_quick_invocation_args_new (GumQuickInterceptor * parent,
    GumQuickInvocationArgs ** args);
static void gum_quick_invocation_args_release (GumQuickInvocationArgs * self);
static void gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
    GumInvocationContext * ic);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_args_finalize)
static JSValue gumjs_invocation_args_get_property (JSContext * ctx,
    JSValueConst obj, JSAtom atom, JSValueConst receiver);
static int gumjs_invocation_args_set_property (JSContext * ctx,
    JSValueConst obj, JSAtom atom, JSValueConst value, JSValueConst receiver,
    int flags);

static JSValue gum_quick_invocation_retval_new (GumQuickInterceptor * parent,
    GumQuickInvocationRetval ** retval);
static void gum_quick_invocation_retval_release (
    GumQuickInvocationRetval * self);
static void gum_quick_invocation_retval_reset (
    GumQuickInvocationRetval * self, GumInvocationContext * ic);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_retval_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_retval_replace)

static void gum_quick_interceptor_check_invocation_context (
    GumQuickInterceptor * self, GumQuickInvocationContext * jic,
    gboolean * jic_is_dirty);
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
  JS_CFUNC_DEF ("_replace", 0, gumjs_interceptor_replace),
  JS_CFUNC_DEF ("_replaceFast", 0, gumjs_interceptor_replace_fast),
  JS_CFUNC_DEF ("revert", 0, gumjs_interceptor_revert),
  JS_CFUNC_DEF ("flush", 0, gumjs_interceptor_flush),
};

static const JSClassDef gumjs_invocation_listener_def =
{
  .class_name = "InvocationListener",
};

static const JSCFunctionListEntry gumjs_invocation_listener_entries[] =
{
  JS_CFUNC_DEF ("detach", 0, gumjs_invocation_listener_detach),
};

static const JSClassDef gumjs_invocation_context_def =
{
  .class_name = "InvocationContext",
  .finalizer = gumjs_invocation_context_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_context_entries[] =
{
  JS_CGETSET_DEF ("returnAddress", gumjs_invocation_context_get_return_address,
      NULL),
  JS_CGETSET_DEF ("context", gumjs_invocation_context_get_cpu_context, NULL),
  JS_CGETSET_DEF (GUMJS_SYSTEM_ERROR_FIELD,
      gumjs_invocation_context_get_system_error,
      gumjs_invocation_context_set_system_error),
  JS_CGETSET_DEF ("threadId", gumjs_invocation_context_get_thread_id, NULL),
  JS_CGETSET_DEF ("depth", gumjs_invocation_context_get_depth, NULL),
};

static const JSClassExoticMethods gumjs_invocation_args_exotic_methods =
{
  .get_property = gumjs_invocation_args_get_property,
  .set_property = gumjs_invocation_args_set_property,
};

static const JSClassDef gumjs_invocation_args_def =
{
  .class_name = "InvocationArguments",
  .finalizer = gumjs_invocation_args_finalize,
  .exotic = (JSClassExoticMethods *) &gumjs_invocation_args_exotic_methods,
};

static const JSClassDef gumjs_invocation_retval_def =
{
  .class_name = "InvocationReturnValue",
  .finalizer = gumjs_invocation_retval_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_retval_entries[] =
{
  JS_CFUNC_DEF ("replace", 0, gumjs_invocation_retval_replace),
};

void
_gum_quick_interceptor_init (GumQuickInterceptor * self,
                             JSValue ns,
                             GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_invocation_listener_destroy);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_replace_entry_revert_and_free);
  self->flush_timer = NULL;

  _gum_quick_core_store_module_data (core, "interceptor", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_interceptor_entries,
      G_N_ELEMENTS (gumjs_interceptor_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Interceptor", obj, JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_invocation_listener_def, core,
      &self->invocation_listener_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_listener_entries,
      G_N_ELEMENTS (gumjs_invocation_listener_entries));

  _gum_quick_create_class (ctx, &gumjs_invocation_context_def, core,
      &self->invocation_context_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_context_entries,
      G_N_ELEMENTS (gumjs_invocation_context_entries));

  _gum_quick_create_class (ctx, &gumjs_invocation_args_def, core,
      &self->invocation_args_class, &proto);

  _gum_quick_create_subclass (ctx, &gumjs_invocation_retval_def,
      core->native_pointer_class, core->native_pointer_proto, core,
      &self->invocation_retval_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_retval_entries,
      G_N_ELEMENTS (gumjs_invocation_retval_entries));

  gum_quick_invocation_context_new (self, &self->cached_invocation_context);
  self->cached_invocation_context_in_use = FALSE;

  gum_quick_invocation_args_new (self, &self->cached_invocation_args);
  self->cached_invocation_args_in_use = FALSE;

  gum_quick_invocation_retval_new (self, &self->cached_invocation_retval);
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
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "interceptor");
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  JSValue target_val = args->elements[0];
  JSValue cb_val = args->elements[1];
  JSValue data_val = args->elements[2];
  GumQuickInterceptor * self;
  gpointer target, cb_ptr;
  GumQuickInvocationListener * listener = NULL;
  gpointer listener_function_data;
  GumAttachReturn attach_ret;

  self = gumjs_get_parent_module (core);

  if (JS_IsFunction (ctx, cb_val))
  {
    GumQuickJSProbeListener * l;

    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      goto propagate_exception;

    l = g_object_new (GUM_QUICK_TYPE_JS_PROBE_LISTENER, NULL);
    l->on_hit = JS_DupValue (ctx, cb_val);

    listener = GUM_QUICK_INVOCATION_LISTENER (l);
  }
  else if (_gum_quick_native_pointer_try_get (ctx, cb_val, core, &cb_ptr))
  {
    GumQuickCProbeListener * l;

    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      goto propagate_exception;

    l = g_object_new (GUM_QUICK_TYPE_C_PROBE_LISTENER, NULL);
    l->on_hit = GUM_POINTER_TO_FUNCPTR (GumQuickCHook, cb_ptr);

    listener = GUM_QUICK_INVOCATION_LISTENER (l);
  }
  else
  {
    JSValue on_enter_js, on_leave_js;
    GumQuickCHook on_enter_c, on_leave_c;

    if (!_gum_quick_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c))
      goto propagate_exception;

    if (!JS_IsNull (on_enter_js) || !JS_IsNull (on_leave_js))
    {
      GumQuickJSCallListener * l;

      l = g_object_new (GUM_QUICK_TYPE_JS_CALL_LISTENER, NULL);
      l->on_enter = JS_DupValue (ctx, on_enter_js);
      l->on_leave = JS_DupValue (ctx, on_leave_js);

      listener = GUM_QUICK_INVOCATION_LISTENER (l);
    }
    else if (on_enter_c != NULL || on_leave_c != NULL)
    {
      GumQuickCCallListener * l;

      l = g_object_new (GUM_QUICK_TYPE_C_CALL_LISTENER, NULL);
      l->on_enter = on_enter_c;
      l->on_leave = on_leave_c;

      listener = GUM_QUICK_INVOCATION_LISTENER (l);
    }
    else
    {
      goto expected_callback;
    }
  }

  if (!JS_IsUndefined (data_val))
  {
    if (!_gum_quick_native_pointer_get (ctx, data_val, core,
        &listener_function_data))
      goto propagate_exception;
  }
  else
  {
    listener_function_data = NULL;
  }

  listener->parent = self;

  attach_ret = gum_interceptor_attach (self->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  listener->wrapper = JS_NewObjectClass (ctx, self->invocation_listener_class);
  JS_SetOpaque (listener->wrapper, listener);
  JS_DefinePropertyValue (ctx, listener->wrapper,
      GUM_QUICK_CORE_ATOM (core, resource),
      JS_DupValue (ctx, cb_val),
      0);

  g_hash_table_add (self->invocation_listeners, listener);

  return JS_DupValue (ctx, listener->wrapper);

unable_to_attach:
  {
    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gum_quick_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gum_quick_throw_literal (ctx, "already attached to this function");
        break;
      case GUM_ATTACH_POLICY_VIOLATION:
        _gum_quick_throw_literal (ctx, "not permitted by code-signing policy");
        break;
      case GUM_ATTACH_WRONG_TYPE:
        _gum_quick_throw_literal (ctx, "wrong type");
        break;
      default:
        g_assert_not_reached ();
    }

    goto propagate_exception;
  }
expected_callback:
  {
    _gum_quick_throw_literal (ctx, "expected at least one callback");
    goto propagate_exception;
  }
propagate_exception:
  {
    g_clear_object (&listener);

    return JS_EXCEPTION;
  }
}

static void
gum_quick_invocation_listener_destroy (GumQuickInvocationListener * listener)
{
  gum_interceptor_detach (listener->parent->interceptor,
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
  GumQuickInterceptor * self = gumjs_get_parent_module (core);

  g_hash_table_remove_all (self->invocation_listeners);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumQuickInterceptor * self;
  gpointer target, replacement_function, replacement_data;
  JSValue replacement_value;
  GumReplaceReturn replace_ret;

  self = gumjs_get_parent_module (core);

  replacement_data = NULL;
  if (!_gum_quick_args_parse (args, "pO|p", &target, &replacement_value,
      &replacement_data))
    return JS_EXCEPTION;

  if (!_gum_quick_native_pointer_get (ctx, replacement_value, core,
      &replacement_function))
    return JS_EXCEPTION;

  replace_ret = gum_interceptor_replace (self->interceptor, target,
      replacement_function, replacement_data, NULL);
  if (replace_ret != GUM_REPLACE_OK)
    return gum_quick_handle_replace_ret (ctx, target, replace_ret);

  gum_quick_add_replace_entry (self, target, replacement_value);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace_fast)
{
  GumQuickInterceptor * self;
  gpointer target, replacement_function, original_function;
  JSValue replacement_value;
  GumReplaceReturn replace_ret;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "pO", &target, &replacement_value))
    return JS_EXCEPTION;

  if (!_gum_quick_native_pointer_get (ctx, replacement_value, core,
      &replacement_function))
    return JS_EXCEPTION;

  replace_ret = gum_interceptor_replace_fast (self->interceptor, target,
      replacement_function, &original_function);
  if (replace_ret != GUM_REPLACE_OK)
    return gum_quick_handle_replace_ret (ctx, target, replace_ret);

  gum_quick_add_replace_entry (self, target, replacement_value);

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (original_function), core);
}

static void
gum_quick_add_replace_entry (GumQuickInterceptor * self,
                             gpointer target,
                             JSValue replacement_value)
{
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;
  GumQuickReplaceEntry * entry;

  entry = g_slice_new (GumQuickReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = JS_DupValue (ctx, replacement_value);
  entry->ctx = ctx;

  g_hash_table_insert (self->replacement_by_address, target, entry);
}

static JSValue
gum_quick_handle_replace_ret (JSContext * ctx,
                              gpointer target,
                              GumReplaceReturn replace_ret)
{
  switch (replace_ret)
  {
    case GUM_REPLACE_WRONG_SIGNATURE:
      _gum_quick_throw (ctx, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    case GUM_REPLACE_ALREADY_REPLACED:
      _gum_quick_throw_literal (ctx, "already replaced this function");
      break;
    case GUM_REPLACE_POLICY_VIOLATION:
      _gum_quick_throw_literal (ctx, "not permitted by code-signing policy");
      break;
    case GUM_REPLACE_WRONG_TYPE:
      _gum_quick_throw_literal (ctx, "wrong type");
      break;
    default:
      g_assert_not_reached ();
  }

  return JS_EXCEPTION;
}

static void
gum_quick_replace_entry_free (GumQuickReplaceEntry * entry)
{
  if (entry == NULL)
    return;

  JS_FreeValue (entry->ctx, entry->replacement);

  g_slice_free (GumQuickReplaceEntry, entry);
}

static void
gum_quick_replace_entry_revert_and_free (GumQuickReplaceEntry * entry)
{
  gum_interceptor_revert (entry->interceptor, entry->target);

  gum_quick_replace_entry_free (entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumQuickInterceptor * self;
  gpointer target;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "p", &target))
    return JS_EXCEPTION;

  g_hash_table_remove (self->replacement_by_address, target);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  GumQuickInterceptor * self = gumjs_get_parent_module (core);

  gum_interceptor_end_transaction (self->interceptor);
  gum_interceptor_begin_transaction (self->interceptor);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_listener_detach)
{
  GumQuickInterceptor * parent;
  GumQuickInvocationListener * listener;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_unwrap (ctx, this_val, parent->invocation_listener_class,
      core, (gpointer *) &listener))
    return JS_EXCEPTION;

  if (listener != NULL)
    gum_quick_interceptor_detach (parent, listener);

  return JS_UNDEFINED;
}

static void
gum_quick_invocation_listener_class_init (
    GumQuickInvocationListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_invocation_listener_dispose;
}

static void
gum_quick_invocation_listener_init (GumQuickInvocationListener * self)
{
  self->wrapper = JS_NULL;
}

static void
gum_quick_invocation_listener_dispose (GObject * object)
{
  g_assert (JS_IsNull (GUM_QUICK_INVOCATION_LISTENER (object)->wrapper));

  G_OBJECT_CLASS (gum_quick_invocation_listener_parent_class)->dispose (object);
}

static void
gum_quick_invocation_listener_release_wrapper (
    GumQuickInvocationListener * self,
    JSContext * ctx)
{
  if (!JS_IsNull (self->wrapper))
  {
    JS_SetOpaque (self->wrapper, NULL);
    JS_FreeValue (ctx, self->wrapper);
    self->wrapper = JS_NULL;
  }
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

  iface->on_enter = gum_quick_js_call_listener_on_enter;
  iface->on_leave = gum_quick_js_call_listener_on_leave;
}

static void
gum_quick_js_call_listener_init (GumQuickJSCallListener * self)
{
}

static void
gum_quick_js_call_listener_dispose (GObject * object)
{
  GumQuickJSCallListener * self;
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  JSContext * ctx;
  GumQuickScope scope;

  self = GUM_QUICK_JS_CALL_LISTENER (object);
  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;
  ctx = core->ctx;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_enter);
  self->on_enter = JS_NULL;

  JS_FreeValue (ctx, self->on_leave);
  self->on_leave = JS_NULL;

  gum_quick_invocation_listener_release_wrapper (base_listener, ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_js_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_js_call_listener_on_enter (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GumQuickJSCallListener * self;
  GumQuickInvocationState * state;

  self = GUM_QUICK_JS_CALL_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (!JS_IsNull (self->on_enter))
  {
    GumQuickInterceptor * parent;
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationArgs * args;
    gboolean jic_is_dirty;

    parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;

    _gum_quick_scope_enter (&scope, parent->core);

    jic = _gum_quick_interceptor_obtain_invocation_context (parent);
    _gum_quick_invocation_context_reset (jic, ic);

    args = gum_quick_interceptor_obtain_invocation_args (parent);
    gum_quick_invocation_args_reset (args, ic);

    _gum_quick_scope_call_void (&scope, self->on_enter, jic->wrapper, 1,
        &args->wrapper);

    gum_quick_invocation_args_reset (args, NULL);
    gum_quick_interceptor_release_invocation_args (parent, args);

    _gum_quick_invocation_context_reset (jic, NULL);
    gum_quick_interceptor_check_invocation_context (parent, jic, &jic_is_dirty);
    if (!JS_IsNull (self->on_leave) || jic_is_dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_quick_interceptor_release_invocation_context (parent, jic);
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
gum_quick_js_call_listener_on_leave (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GumQuickJSCallListener * self;
  GumQuickInterceptor * parent;
  GumQuickInvocationState * state;

  self = GUM_QUICK_JS_CALL_LISTENER_CAST (listener);
  parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (!JS_IsNull (self->on_leave))
  {
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationRetval * retval;

    _gum_quick_scope_enter (&scope, parent->core);

    jic = !JS_IsNull (self->on_enter) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_quick_interceptor_obtain_invocation_context (parent);
    }
    _gum_quick_invocation_context_reset (jic, ic);

    retval = gum_quick_interceptor_obtain_invocation_retval (parent);
    gum_quick_invocation_retval_reset (retval, ic);

    _gum_quick_scope_call_void (&scope, self->on_leave, jic->wrapper, 1,
        &retval->wrapper);

    gum_quick_invocation_retval_reset (retval, NULL);
    gum_quick_interceptor_release_invocation_retval (parent, retval);

    _gum_quick_invocation_context_reset (jic, NULL);
    gum_quick_interceptor_check_invocation_context (parent, jic, NULL);
    _gum_quick_interceptor_release_invocation_context (parent, jic);

    _gum_quick_scope_leave (&scope);
  }
  else if (state->jic != NULL)
  {
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, parent->core);

    _gum_quick_interceptor_release_invocation_context (parent, state->jic);

    _gum_quick_scope_leave (&scope);
  }
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

  iface->on_enter = gum_quick_js_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_js_probe_listener_init (GumQuickJSProbeListener * self)
{
}

static void
gum_quick_js_probe_listener_dispose (GObject * object)
{
  GumQuickJSProbeListener * self;
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  JSContext * ctx;
  GumQuickScope scope;

  self = GUM_QUICK_JS_PROBE_LISTENER (object);
  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;
  ctx = core->ctx;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_hit);
  self->on_hit = JS_NULL;

  gum_quick_invocation_listener_release_wrapper (base_listener, ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_quick_js_probe_listener_on_enter (GumInvocationListener * listener,
                                      GumInvocationContext * ic)
{
  GumQuickJSProbeListener * self;
  GumQuickInterceptor * parent;
  GumQuickScope scope;
  GumQuickInvocationContext * jic;
  GumQuickInvocationArgs * args;

  self = GUM_QUICK_JS_PROBE_LISTENER_CAST (listener);
  parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;

  _gum_quick_scope_enter (&scope, parent->core);

  jic = _gum_quick_interceptor_obtain_invocation_context (parent);
  _gum_quick_invocation_context_reset (jic, ic);

  args = gum_quick_interceptor_obtain_invocation_args (parent);
  gum_quick_invocation_args_reset (args, ic);

  _gum_quick_scope_call_void (&scope, self->on_hit, jic->wrapper, 1,
      &args->wrapper);

  gum_quick_invocation_args_reset (args, NULL);
  gum_quick_interceptor_release_invocation_args (parent, args);

  _gum_quick_invocation_context_reset (jic, NULL);
  _gum_quick_interceptor_release_invocation_context (parent, jic);

  _gum_quick_scope_leave (&scope);
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

  iface->on_enter = gum_quick_c_call_listener_on_enter;
  iface->on_leave = gum_quick_c_call_listener_on_leave;
}

static void
gum_quick_c_call_listener_init (GumQuickCCallListener * self)
{
}

static void
gum_quick_c_call_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  GumQuickScope scope;

  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;

  _gum_quick_scope_enter (&scope, core);

  gum_quick_invocation_listener_release_wrapper (base_listener, core->ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_c_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_call_listener_on_enter (GumInvocationListener * listener,
                                    GumInvocationContext * ic)
{
  GumQuickCCallListener * self = GUM_QUICK_C_CALL_LISTENER_CAST (listener);

  if (self->on_enter != NULL)
    self->on_enter (ic);
}

static void
gum_quick_c_call_listener_on_leave (GumInvocationListener * listener,
                                    GumInvocationContext * ic)
{
  GumQuickCCallListener * self = GUM_QUICK_C_CALL_LISTENER_CAST (listener);

  if (self->on_leave != NULL)
    self->on_leave (ic);
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

  iface->on_enter = gum_quick_c_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_c_probe_listener_init (GumQuickCProbeListener * self)
{
}

static void
gum_quick_c_probe_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  GumQuickScope scope;

  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;

  _gum_quick_scope_enter (&scope, core);

  gum_quick_invocation_listener_release_wrapper (base_listener, core->ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_c_probe_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_probe_listener_on_enter (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GUM_QUICK_C_PROBE_LISTENER_CAST (listener)->on_hit (ic);
}

static JSValue
gum_quick_invocation_context_new (GumQuickInterceptor * parent,
                                  GumQuickInvocationContext ** context)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationContext * jic;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_context_class);

  jic = g_slice_new (GumQuickInvocationContext);
  jic->wrapper = wrapper;
  jic->handle = NULL;
  jic->cpu_context = NULL;
  jic->initial_property_count = JS_GetOwnPropertyCountUnchecked (wrapper);
  jic->interceptor = parent;

  JS_SetOpaque (wrapper, jic);

  *context = jic;

  return wrapper;
}

static void
gum_quick_invocation_context_release (GumQuickInvocationContext * self)
{
  JS_FreeValue (self->interceptor->core->ctx, self->wrapper);
}

void
_gum_quick_invocation_context_reset (GumQuickInvocationContext * self,
                                     GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != NULL)
  {
    _gum_quick_cpu_context_make_read_only (self->cpu_context);
    JS_FreeValue (self->interceptor->core->ctx, self->cpu_context->wrapper);
    self->cpu_context = NULL;
  }
}

static gboolean
gum_quick_invocation_context_get (JSContext * ctx,
                                  JSValueConst val,
                                  GumQuickCore * core,
                                  GumQuickInvocationContext ** ic)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_context_class, core,
      (gpointer *) ic);
}

static gboolean
gum_quick_invocation_context_is_dirty (GumQuickInvocationContext * self)
{
  return JS_GetOwnPropertyCountUnchecked (self->wrapper) !=
      self->initial_property_count;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumQuickInvocationContext * c;

  c = JS_GetOpaque (val,
      gumjs_get_parent_module (core)->invocation_context_class);
  if (c == NULL)
    return;

  g_slice_free (GumQuickInvocationContext, c);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      gum_invocation_context_get_return_address (self->handle), core);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self->cpu_context == NULL)
  {
    _gum_quick_cpu_context_new (ctx, self->handle->cpu_context,
        GUM_CPU_CONTEXT_READWRITE, core, &self->cpu_context);
  }

  return JS_DupValue (ctx, self->cpu_context->wrapper);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, self->handle->system_error);
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  GumQuickInvocationContext * self;
  gint value;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_int_get (ctx, val, &value))
    return JS_EXCEPTION;

  self->handle->system_error = value;

  return JS_UNDEFINED;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx,
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, gum_invocation_context_get_depth (self->handle));
}

static JSValue
gum_quick_invocation_args_new (GumQuickInterceptor * parent,
                               GumQuickInvocationArgs ** args)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationArgs * ia;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_args_class);

  ia = g_slice_new (GumQuickInvocationArgs);
  ia->wrapper = wrapper;
  ia->ic = NULL;
  ia->ctx = ctx;

  JS_SetOpaque (wrapper, ia);

  *args = ia;

  return wrapper;
}

static void
gum_quick_invocation_args_release (GumQuickInvocationArgs * self)
{
  JS_FreeValue (self->ctx, self->wrapper);
}

static void
gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
                                 GumInvocationContext * ic)
{
  self->ic = ic;
}

static gboolean
gum_quick_invocation_args_get (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               GumQuickInvocationArgs ** args)
{
  GumQuickInvocationArgs * a;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_args_class, core,
      (gpointer *) &a))
    return FALSE;

  if (a->ic == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *args = a;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_args_finalize)
{
  GumQuickInvocationArgs * a;

  a = JS_GetOpaque (val, gumjs_get_parent_module (core)->invocation_args_class);
  if (a == NULL)
    return;

  g_slice_free (GumQuickInvocationArgs, a);
}

static JSValue
gumjs_invocation_args_get_property (JSContext * ctx,
                                    JSValueConst obj,
                                    JSAtom atom,
                                    JSValueConst receiver)
{
  JSValue result;
  const char * prop_name;

  prop_name = JS_AtomToCString (ctx, atom);

  if (strcmp (prop_name, "toJSON") == 0)
  {
    result = JS_NewString (ctx, "invocation-args");
  }
  else
  {
    GumQuickCore * core;
    GumQuickInvocationArgs * self;
    guint64 n;
    const gchar * end;

    core = JS_GetContextOpaque (ctx);

    if (!gum_quick_invocation_args_get (ctx, receiver, core, &self))
      goto propagate_exception;

    n = g_ascii_strtoull (prop_name, (gchar **) &end, 10);
    if (end != prop_name + strlen (prop_name))
      goto invalid_array_index;

    result = _gum_quick_native_pointer_new (ctx,
        gum_invocation_context_get_nth_argument (self->ic, n), core);
  }

  JS_FreeCString (ctx, prop_name);

  return result;

invalid_array_index:
  {
    JS_ThrowRangeError (ctx, "invalid array index");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeCString (ctx, prop_name);

    return JS_EXCEPTION;
  }
}

static int
gumjs_invocation_args_set_property (JSContext * ctx,
                                    JSValueConst obj,
                                    JSAtom atom,
                                    JSValueConst value,
                                    JSValueConst receiver,
                                    int flags)
{
  const char * prop_name;
  GumQuickCore * core;
  GumQuickInvocationArgs * self;
  guint64 n;
  const gchar * end;
  gpointer v;

  prop_name = JS_AtomToCString (ctx, atom);

  core = JS_GetContextOpaque (ctx);

  if (!gum_quick_invocation_args_get (ctx, receiver, core, &self))
    goto propagate_exception;

  n = g_ascii_strtoull (prop_name, (gchar **) &end, 10);
  if (end != prop_name + strlen (prop_name))
    goto invalid_array_index;

  if (!_gum_quick_native_pointer_get (ctx, value, core, &v))
    goto propagate_exception;

  gum_invocation_context_replace_nth_argument (self->ic, n, v);

  JS_FreeCString (ctx, prop_name);

  return TRUE;

invalid_array_index:
  {
    JS_ThrowRangeError (ctx, "invalid array index");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeCString (ctx, prop_name);

    return -1;
  }
}

static JSValue
gum_quick_invocation_retval_new (GumQuickInterceptor * parent,
                                 GumQuickInvocationRetval ** retval)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationRetval * rv;
  GumQuickNativePointer * ptr;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_retval_class);

  rv = g_slice_new (GumQuickInvocationRetval);
  ptr = &rv->native_pointer;
  ptr->value = NULL;
  rv->wrapper = wrapper;
  rv->ic = NULL;
  rv->ctx = ctx;

  JS_SetOpaque (wrapper, rv);

  *retval = rv;

  return wrapper;
}

static void
gum_quick_invocation_retval_release (GumQuickInvocationRetval * self)
{
  JS_FreeValue (self->ctx, self->wrapper);
}

static void
gum_quick_invocation_retval_reset (GumQuickInvocationRetval * self,
                                   GumInvocationContext * ic)
{
  GumQuickNativePointer * ptr;

  ptr = &self->native_pointer;
  if (ic != NULL)
    ptr->value = gum_invocation_context_get_return_value (ic);
  else
    ptr->value = NULL;

  self->ic = ic;
}

static gboolean
gum_quick_invocation_retval_get (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 GumQuickInvocationRetval ** retval)
{
  GumQuickInvocationRetval * r;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_retval_class, core,
      (gpointer *) &r))
    return FALSE;

  if (r->ic == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *retval = r;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_retval_finalize)
{
  GumQuickInvocationRetval * r;

  r = JS_GetOpaque (val,
      gumjs_get_parent_module (core)->invocation_retval_class);
  if (r == NULL)
    return;

  g_slice_free (GumQuickInvocationRetval, r);
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_retval_replace)
{
  GumQuickInvocationRetval * self;
  gpointer v;

  if (!gum_quick_invocation_retval_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p~", &v))
    return JS_EXCEPTION;

  self->native_pointer.value = v;

  gum_invocation_context_replace_return_value (self->ic, v);

  return JS_UNDEFINED;
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
    gum_quick_invocation_context_new (self, &jic);
  }

  return jic;
}

void
_gum_quick_interceptor_release_invocation_context (
    GumQuickInterceptor * self,
    GumQuickInvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_quick_invocation_context_release (jic);
}

static void
gum_quick_interceptor_check_invocation_context (GumQuickInterceptor * self,
                                                GumQuickInvocationContext * jic,
                                                gboolean * jic_is_dirty)
{
  gboolean is_dirty;

  is_dirty = gum_quick_invocation_context_is_dirty (jic);

  if (is_dirty && jic == self->cached_invocation_context)
  {
    gum_quick_invocation_context_new (self, &self->cached_invocation_context);
    self->cached_invocation_context_in_use = FALSE;
  }

  if (jic_is_dirty != NULL)
    *jic_is_dirty = is_dirty;
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
    gum_quick_invocation_args_new (self, &args);
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
    gum_quick_invocation_retval_new (self, &retval);
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
