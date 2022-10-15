/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <errno.h>

#define GUMJS_MODULE_NAME Interceptor

#define GUM_V8_TYPE_INVOCATION_LISTENER (gum_v8_invocation_listener_get_type ())
#define GUM_V8_TYPE_JS_CALL_LISTENER (gum_v8_js_call_listener_get_type ())
#define GUM_V8_TYPE_JS_PROBE_LISTENER (gum_v8_js_probe_listener_get_type ())
#define GUM_V8_TYPE_C_CALL_LISTENER (gum_v8_c_call_listener_get_type ())
#define GUM_V8_TYPE_C_PROBE_LISTENER (gum_v8_c_probe_listener_get_type ())

#define GUM_V8_INVOCATION_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_INVOCATION_LISTENER, \
        GumV8InvocationListener)
#define GUM_V8_JS_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_JS_CALL_LISTENER, \
        GumV8JSCallListener)
#define GUM_V8_JS_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_JS_PROBE_LISTENER, \
        GumV8JSProbeListener)
#define GUM_V8_C_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_C_CALL_LISTENER, \
        GumV8CCallListener)
#define GUM_V8_C_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_C_PROBE_LISTENER, \
        GumV8CProbeListener)

#define GUM_V8_INVOCATION_LISTENER_CAST(obj) ((GumV8InvocationListener *) (obj))
#define GUM_V8_JS_CALL_LISTENER_CAST(obj) ((GumV8JSCallListener *) (obj))
#define GUM_V8_JS_PROBE_LISTENER_CAST(obj) ((GumV8JSProbeListener *) (obj))
#define GUM_V8_C_CALL_LISTENER_CAST(obj) ((GumV8CCallListener *) (obj))
#define GUM_V8_C_PROBE_LISTENER_CAST(obj) ((GumV8CProbeListener *) (obj))

using namespace v8;

typedef void (* GumV8CHook) (GumInvocationContext * ic);

struct GumV8InvocationListener
{
  GObject object;

  Global<Object> * resource;

  GumV8Interceptor * module;
};

struct GumV8InvocationListenerClass
{
  GObjectClass object_class;
};

struct GumV8JSCallListener
{
  GumV8InvocationListener listener;

  Global<Function> * on_enter;
  Global<Function> * on_leave;
};

struct GumV8JSCallListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8JSProbeListener
{
  GumV8InvocationListener listener;

  Global<Function> * on_hit;
};

struct GumV8JSProbeListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8CCallListener
{
  GumV8InvocationListener listener;

  GumV8CHook on_enter;
  GumV8CHook on_leave;
};

struct GumV8CCallListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8CProbeListener
{
  GumV8InvocationListener listener;

  GumV8CHook on_hit;
};

struct GumV8CProbeListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8InvocationState
{
  GumV8InvocationContext * jic;
};

struct GumV8InvocationArgs
{
  Global<Object> * object;
  GumInvocationContext * ic;

  GumV8Interceptor * module;
};

struct GumV8InvocationReturnValue
{
  Global<Object> * object;
  GumInvocationContext * ic;

  GumV8Interceptor * module;
};

struct GumV8ReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  Global<Value> * replacement;
};

static gboolean gum_v8_interceptor_on_flush_timer_tick (
    GumV8Interceptor * self);

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_v8_invocation_listener_destroy (
    GumV8InvocationListener * listener);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_v8_replace_entry_free (GumV8ReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)
static void gum_v8_invocation_listener_dispose (GObject * object);
static void gum_v8_invocation_listener_release_resource (
    GumV8InvocationListener * self);
G_DEFINE_TYPE_EXTENDED (GumV8InvocationListener,
                        gum_v8_invocation_listener,
                        G_TYPE_OBJECT,
                        G_TYPE_FLAG_ABSTRACT,
                        {})

static void gum_v8_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_js_call_listener_dispose (GObject * object);
static void gum_v8_js_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_v8_js_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8JSCallListener,
                        gum_v8_js_call_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_js_call_listener_iface_init))

static void gum_v8_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_js_probe_listener_dispose (GObject * object);
static void gum_v8_js_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8JSProbeListener,
                        gum_v8_js_probe_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_js_probe_listener_iface_init))

static void gum_v8_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_c_call_listener_dispose (GObject * object);
static void gum_v8_c_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_v8_c_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8CCallListener,
                        gum_v8_c_call_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_c_call_listener_iface_init))

static void gum_v8_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_c_probe_listener_dispose (GObject * object);
static void gum_v8_c_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8CProbeListener,
                        gum_v8_c_probe_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_c_probe_listener_iface_init))

static GumV8InvocationContext * gum_v8_invocation_context_new_persistent (
    GumV8Interceptor * parent);
static void gum_v8_invocation_context_release_persistent (
    GumV8InvocationContext * self);
static void gum_v8_invocation_context_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationContext> & info);
static void gum_v8_invocation_context_free (GumV8InvocationContext * self);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
static void gumjs_invocation_context_set_property (Local<Name> property,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationArgs * gum_v8_invocation_args_new_persistent (
    GumV8Interceptor * parent);
static void gum_v8_invocation_args_release_persistent (
    GumV8InvocationArgs * self);
static void gum_v8_invocation_args_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationArgs> & info);
static void gum_v8_invocation_args_free (GumV8InvocationArgs * self);
static void gum_v8_invocation_args_reset (GumV8InvocationArgs * self,
    GumInvocationContext * ic);
static void gumjs_invocation_args_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_args_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationReturnValue *
    gum_v8_invocation_return_value_new_persistent (GumV8Interceptor * parent);
static void gum_v8_invocation_return_value_release_persistent (
    GumV8InvocationReturnValue * self);
static void gum_v8_invocation_return_value_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationReturnValue> & info);
static void gum_v8_invocation_return_value_free (
    GumV8InvocationReturnValue * self);
static void gum_v8_invocation_return_value_reset (
    GumV8InvocationReturnValue * self, GumInvocationContext * ic);
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

static GumV8InvocationArgs * gum_v8_interceptor_obtain_invocation_args (
    GumV8Interceptor * self);
static void gum_v8_interceptor_release_invocation_args (GumV8Interceptor * self,
    GumV8InvocationArgs * args);
static GumV8InvocationReturnValue *
    gum_v8_interceptor_obtain_invocation_return_value (GumV8Interceptor * self);
static void gum_v8_interceptor_release_invocation_return_value (
    GumV8Interceptor * self, GumV8InvocationReturnValue * retval);

static const GumV8Function gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach },
  { "detachAll", gumjs_interceptor_detach_all },
  { "_replace", gumjs_interceptor_replace },
  { "revert", gumjs_interceptor_revert },
  { "flush", gumjs_interceptor_flush },

  { NULL, NULL }
};

static const GumV8Function gumjs_invocation_listener_functions[] =
{
  { "detach", gumjs_invocation_listener_detach },

  { NULL, NULL }
};

static const GumV8Property gumjs_invocation_context_values[] =
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

static const GumV8Function gumjs_invocation_return_value_functions[] =
{
  { "replace", gumjs_invocation_return_value_replace },

  { NULL, NULL }
};

void
_gum_v8_interceptor_init (GumV8Interceptor * self,
                          GumV8Core * core,
                          Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_listener_destroy);
  self->invocation_context_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_context_free);
  self->invocation_args_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_args_free);
  self->invocation_return_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_return_value_free);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_replace_entry_free);
  self->flush_timer = NULL;

  auto module = External::New (isolate, self);

  auto interceptor = _gum_v8_create_module ("Interceptor", scope, isolate);
  _gum_v8_module_add (module, interceptor, gumjs_interceptor_functions,
      isolate);

  auto listener = _gum_v8_create_class ("InvocationListener", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (listener, gumjs_invocation_listener_functions, module,
      isolate);
  self->invocation_listener = new Global<FunctionTemplate> (isolate, listener);

  auto ic = _gum_v8_create_class ("InvocationContext", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (ic, gumjs_invocation_context_values, module, isolate);
  NamedPropertyHandlerConfiguration ic_access;
  ic_access.setter = gumjs_invocation_context_set_property;
  ic_access.data = module;
  ic_access.flags = PropertyHandlerFlags::kNonMasking;
  ic->InstanceTemplate ()->SetHandler (ic_access);
  self->invocation_context = new Global<FunctionTemplate> (isolate, ic);

  auto ia = _gum_v8_create_class ("InvocationArgs", nullptr, scope, module,
      isolate);
  ia->InstanceTemplate ()->SetIndexedPropertyHandler (
      gumjs_invocation_args_get_nth, gumjs_invocation_args_set_nth, nullptr,
      nullptr, nullptr, module);
  self->invocation_args = new Global<FunctionTemplate> (isolate, ia);

  auto ir = _gum_v8_create_class ("InvocationReturnValue", nullptr, scope,
      module, isolate);
  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  ir->Inherit (native_pointer);
  _gum_v8_class_add (ir, gumjs_invocation_return_value_functions, module,
      isolate);
  ir->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return = new Global<FunctionTemplate> (isolate, ir);
}

void
_gum_v8_interceptor_realize (GumV8Interceptor * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto listener = Local<FunctionTemplate>::New (isolate,
      *self->invocation_listener);
  auto listener_value = listener->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_listener_value =
      new Global<Object> (isolate, listener_value);

  auto ic = Local<FunctionTemplate>::New (isolate, *self->invocation_context);
  auto ic_value = ic->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_context_value = new Global<Object> (isolate, ic_value);

  auto ia = Local<FunctionTemplate>::New (isolate, *self->invocation_args);
  auto ia_value = ia->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_args_value = new Global<Object> (isolate, ia_value);

  auto ir = Local<FunctionTemplate>::New (isolate, *self->invocation_return);
  auto ir_value = ir->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_return_value = new Global<Object> (isolate, ir_value);

  self->cached_invocation_context =
      gum_v8_invocation_context_new_persistent (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args =
      gum_v8_invocation_args_new_persistent (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_return_value =
      gum_v8_invocation_return_value_new_persistent (self);
  self->cached_invocation_return_value_in_use = FALSE;
}

void
_gum_v8_interceptor_flush (GumV8Interceptor * self)
{
  auto core = self->core;
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  {
    ScriptUnlocker unlocker (core);

    flushed = gum_interceptor_flush (self->interceptor);
  }

  if (!flushed && self->flush_timer == NULL)
  {
    auto source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_interceptor_on_flush_timer_tick, self, NULL);
    self->flush_timer = source;

    _gum_v8_core_pin (core);

    {
      ScriptUnlocker unlocker (core);

      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
      g_source_unref (source);
    }
  }
}

static gboolean
gum_v8_interceptor_on_flush_timer_tick (GumV8Interceptor * self)
{
  gboolean flushed = gum_interceptor_flush (self->interceptor);
  if (flushed)
  {
    GumV8Core * core = self->core;

    ScriptScope scope (core->script);
    _gum_v8_core_unpin (core);
    self->flush_timer = NULL;
  }

  return !flushed;
}

void
_gum_v8_interceptor_dispose (GumV8Interceptor * self)
{
  g_assert (self->flush_timer == NULL);

  gum_v8_invocation_context_release_persistent (
      self->cached_invocation_context);
  gum_v8_invocation_args_release_persistent (
      self->cached_invocation_args);
  gum_v8_invocation_return_value_release_persistent (
      self->cached_invocation_return_value);
  self->cached_invocation_context = NULL;
  self->cached_invocation_args = NULL;
  self->cached_invocation_return_value = NULL;

  delete self->invocation_return_value;
  self->invocation_return_value = nullptr;

  delete self->invocation_args_value;
  self->invocation_args_value = nullptr;

  delete self->invocation_context_value;
  self->invocation_context_value = nullptr;

  delete self->invocation_listener_value;
  self->invocation_listener_value = nullptr;

  delete self->invocation_return;
  self->invocation_return = nullptr;

  delete self->invocation_args;
  self->invocation_args = nullptr;

  delete self->invocation_context;
  self->invocation_context = nullptr;

  delete self->invocation_listener;
  self->invocation_listener = nullptr;

  g_hash_table_unref (self->invocation_context_values);
  self->invocation_context_values = NULL;

  g_hash_table_unref (self->invocation_args_values);
  self->invocation_args_values = NULL;

  g_hash_table_unref (self->invocation_return_values);
  self->invocation_return_values = NULL;
}

void
_gum_v8_interceptor_finalize (GumV8Interceptor * self)
{
  g_hash_table_unref (self->invocation_listeners);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  if (info.Length () < 3)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gpointer target;
  GumV8InvocationListener * listener;
  auto target_val = info[0];
  auto callback_val = info[1];
  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  if (callback_val->IsFunction ())
  {
    if (!_gum_v8_native_pointer_get (target_val, &target, core))
      return;

    auto l = GUM_V8_JS_PROBE_LISTENER (
        g_object_new (GUM_V8_TYPE_JS_PROBE_LISTENER, NULL));
    l->on_hit = new Global<Function> (isolate, callback_val.As<Function> ());

    listener = GUM_V8_INVOCATION_LISTENER (l);
  }
  else if (native_pointer->HasInstance (callback_val))
  {
    if (!_gum_v8_native_pointer_get (target_val, &target, core))
      return;

    auto l = GUM_V8_C_PROBE_LISTENER (
        g_object_new (GUM_V8_TYPE_C_PROBE_LISTENER, NULL));
    l->on_hit = GUM_POINTER_TO_FUNCPTR (GumV8CHook,
        GUMJS_NATIVE_POINTER_VALUE (callback_val.As<Object> ()));

    listener = GUM_V8_INVOCATION_LISTENER (l);
  }
  else
  {
    Local<Function> on_enter_js, on_leave_js;
    GumV8CHook on_enter_c, on_leave_c;

    if (!_gum_v8_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c))
    {
      return;
    }

    if (!on_enter_js.IsEmpty () || !on_leave_js.IsEmpty ())
    {
      auto l = GUM_V8_JS_CALL_LISTENER (
          g_object_new (GUM_V8_TYPE_JS_CALL_LISTENER, NULL));
      if (!on_enter_js.IsEmpty ())
        l->on_enter = new Global<Function> (isolate, on_enter_js);
      if (!on_leave_js.IsEmpty ())
        l->on_leave = new Global<Function> (isolate, on_leave_js);

      listener = GUM_V8_INVOCATION_LISTENER (l);
    }
    else if (on_enter_c != NULL || on_leave_c != NULL)
    {
      auto l = GUM_V8_C_CALL_LISTENER (
          g_object_new (GUM_V8_TYPE_C_CALL_LISTENER, NULL));
      l->on_enter = on_enter_c;
      l->on_leave = on_leave_c;

      listener = GUM_V8_INVOCATION_LISTENER (l);
    }
    else
    {
      _gum_v8_throw_ascii_literal (isolate, "expected at least one callback");
      return;
    }
  }

  listener->resource = new Global<Object> (isolate, callback_val.As<Object> ());
  listener->module = module;

  gpointer listener_function_data;
  auto data_val = info[2];
  if (!data_val->IsUndefined ())
  {
    if (!_gum_v8_native_pointer_get (data_val, &listener_function_data, core))
    {
      g_object_unref (listener);
      return;
    }
  }
  else
  {
    listener_function_data = NULL;
  }

  auto attach_ret = gum_interceptor_attach (module->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret == GUM_ATTACH_OK)
  {
    auto listener_template_value (Local<Object>::New (isolate,
        *module->invocation_listener_value));
    auto listener_value (listener_template_value->Clone ());
    listener_value->SetAlignedPointerInInternalField (0, listener);

    g_hash_table_add (module->invocation_listeners, listener);

    info.GetReturnValue ().Set (listener_value);
  }
  else
  {
    g_object_unref (listener);
  }

  switch (attach_ret)
  {
    case GUM_ATTACH_OK:
      break;
    case GUM_ATTACH_WRONG_SIGNATURE:
    {
      _gum_v8_throw_ascii (isolate, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    }
    case GUM_ATTACH_ALREADY_ATTACHED:
      _gum_v8_throw_ascii_literal (isolate,
          "already attached to this function");
      break;
    case GUM_ATTACH_POLICY_VIOLATION:
      _gum_v8_throw_ascii_literal (isolate,
          "not permitted by code-signing policy");
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_invocation_listener_destroy (GumV8InvocationListener * listener)
{
  gum_interceptor_detach (listener->module->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_v8_interceptor_detach (GumV8Interceptor * self,
                           GumV8InvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  g_hash_table_remove_all (module->invocation_listeners);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  gpointer target, replacement_function, replacement_data = NULL;
  if (!_gum_v8_args_parse (args, "pp|p", &target, &replacement_function,
      &replacement_data))
    return;
  auto replacement_function_value = info[1];

  auto entry = g_slice_new (GumV8ReplaceEntry);
  entry->interceptor = module->interceptor;
  entry->target = target;
  entry->replacement = new Global<Value> (isolate, replacement_function_value);

  auto replace_ret = gum_interceptor_replace (module->interceptor, target,
      replacement_function, replacement_data, NULL);

  if (replace_ret == GUM_REPLACE_OK)
  {
    auto native_callback = Local<FunctionTemplate>::New (isolate,
        *core->native_callback);
    auto instance = replacement_function_value.As<Object> ();
    if (native_callback->HasInstance (instance))
    {
      auto callback = (GumV8NativeCallback *)
          instance->GetInternalField (1).As<External> ()->Value ();
      callback->interceptor_replacement_count++;
    }

    g_hash_table_insert (module->replacement_by_address, target, entry);
  }
  else
  {
    delete entry->replacement;
    g_slice_free (GumV8ReplaceEntry, entry);
  }

  switch (replace_ret)
  {
    case GUM_REPLACE_OK:
      break;
    case GUM_REPLACE_WRONG_SIGNATURE:
    {
      _gum_v8_throw_ascii (isolate, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    }
    case GUM_REPLACE_ALREADY_REPLACED:
      _gum_v8_throw_ascii_literal (isolate, "already replaced this function");
      break;
    case GUM_REPLACE_POLICY_VIOLATION:
      _gum_v8_throw_ascii_literal (isolate,
          "not permitted by code-signing policy");
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_replace_entry_free (GumV8ReplaceEntry * entry)
{
  gum_interceptor_revert (entry->interceptor, entry->target);

  delete entry->replacement;

  g_slice_free (GumV8ReplaceEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  gpointer target;
  if (!_gum_v8_args_parse (args, "p", &target))
    return;

  auto entry = (GumV8ReplaceEntry *)
      g_hash_table_lookup (module->replacement_by_address, target);
  if (entry != NULL)
  {
    auto native_callback = Local<FunctionTemplate>::New (isolate,
        *core->native_callback);
    auto replacement_value (Local<Value>::New (isolate, *entry->replacement));
    auto instance = replacement_value.As<Object> ();
    if (native_callback->HasInstance (instance))
    {
      auto callback = (GumV8NativeCallback *)
          instance->GetInternalField (1).As<External> ()->Value ();
      callback->interceptor_replacement_count--;
    }
  }

  g_hash_table_remove (module->replacement_by_address, target);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  auto interceptor = module->interceptor;

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_invocation_listener_detach,
                           GumV8InvocationListener)
{
  if (self != NULL)
  {
    wrapper->SetAlignedPointerInInternalField (0, NULL);

    gum_v8_interceptor_detach (module, self);
  }
}

static void
gum_v8_invocation_listener_class_init (GumV8InvocationListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_invocation_listener_dispose;
}

static void
gum_v8_invocation_listener_init (GumV8InvocationListener * self)
{
}

static void
gum_v8_invocation_listener_dispose (GObject * object)
{
  g_assert (GUM_V8_INVOCATION_LISTENER (object)->resource == nullptr);

  G_OBJECT_CLASS (gum_v8_invocation_listener_parent_class)->dispose (object);
}

static void
gum_v8_invocation_listener_release_resource (GumV8InvocationListener * self)
{
  delete self->resource;
  self->resource = nullptr;
}

static void
gum_v8_js_call_listener_class_init (GumV8JSCallListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_js_call_listener_dispose;
}

static void
gum_v8_js_call_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_js_call_listener_on_enter;
  iface->on_leave = gum_v8_js_call_listener_on_leave;
}

static void
gum_v8_js_call_listener_init (GumV8JSCallListener * self)
{
}

static void
gum_v8_js_call_listener_dispose (GObject * object)
{
  auto self = GUM_V8_JS_CALL_LISTENER (object);
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    delete self->on_enter;
    self->on_enter = nullptr;

    delete self->on_leave;
    self->on_leave = nullptr;

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_js_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_js_call_listener_on_enter (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_CALL_LISTENER_CAST (listener);
  auto state = GUM_IC_GET_INVOCATION_DATA (ic, GumV8InvocationState);

  if (self->on_enter != nullptr)
  {
    auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
    auto core = module->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto on_enter = Local<Function>::New (isolate, *self->on_enter);

    auto jic = _gum_v8_interceptor_obtain_invocation_context (module);
    _gum_v8_invocation_context_reset (jic, ic);
    auto recv = Local<Object>::New (isolate, *jic->object);

    auto args = gum_v8_interceptor_obtain_invocation_args (module);
    gum_v8_invocation_args_reset (args, ic);
    auto args_object = Local<Object>::New (isolate, *args->object);

    Local<Value> argv[] = { args_object };
    auto result = on_enter->Call (context, recv, G_N_ELEMENTS (argv), argv);
    if (result.IsEmpty ())
      scope.ProcessAnyPendingException ();

    gum_v8_invocation_args_reset (args, NULL);
    gum_v8_interceptor_release_invocation_args (module, args);

    _gum_v8_invocation_context_reset (jic, NULL);
    if (self->on_leave != nullptr || jic->dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_v8_interceptor_release_invocation_context (module, jic);
      state->jic = NULL;
    }
  }
  else
  {
    state->jic = NULL;
  }
}

static void
gum_v8_js_call_listener_on_leave (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_CALL_LISTENER_CAST (listener);
  auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
  auto core = module->core;
  auto state = GUM_IC_GET_INVOCATION_DATA (ic, GumV8InvocationState);

  if (self->on_leave != nullptr)
  {
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto on_leave = Local<Function>::New (isolate, *self->on_leave);

    auto jic = (self->on_enter != nullptr) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_v8_interceptor_obtain_invocation_context (module);
    }
    _gum_v8_invocation_context_reset (jic, ic);
    auto recv = Local<Object>::New (isolate, *jic->object);

    auto retval = gum_v8_interceptor_obtain_invocation_return_value (module);
    gum_v8_invocation_return_value_reset (retval, ic);
    auto retval_object = Local<Object>::New (isolate, *retval->object);
    retval_object->SetInternalField (0, BigInt::NewFromUnsigned (isolate,
        GPOINTER_TO_SIZE (gum_invocation_context_get_return_value (ic))));

    Local<Value> argv[] = { retval_object };
    auto result = on_leave->Call (context, recv, G_N_ELEMENTS (argv), argv);
    if (result.IsEmpty ())
      scope.ProcessAnyPendingException ();

    gum_v8_invocation_return_value_reset (retval, NULL);
    gum_v8_interceptor_release_invocation_return_value (module, retval);

    _gum_v8_invocation_context_reset (jic, NULL);
    _gum_v8_interceptor_release_invocation_context (module, jic);
  }
  else if (state->jic != NULL)
  {
    ScriptScope scope (core->script);

    _gum_v8_interceptor_release_invocation_context (module, state->jic);
  }
}

static void
gum_v8_js_probe_listener_class_init (GumV8JSProbeListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_js_probe_listener_dispose;
}

static void
gum_v8_js_probe_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_js_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_v8_js_probe_listener_init (GumV8JSProbeListener * self)
{
}

static void
gum_v8_js_probe_listener_dispose (GObject * object)
{
  auto self = GUM_V8_JS_PROBE_LISTENER (object);
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    delete self->on_hit;
    self->on_hit = nullptr;

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_v8_js_probe_listener_on_enter (GumInvocationListener * listener,
                                   GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_PROBE_LISTENER_CAST (listener);
  auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
  auto core = module->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto on_hit = Local<Function>::New (isolate, *self->on_hit);

  auto jic = _gum_v8_interceptor_obtain_invocation_context (module);
  _gum_v8_invocation_context_reset (jic, ic);
  auto recv = Local<Object>::New (isolate, *jic->object);

  auto args = gum_v8_interceptor_obtain_invocation_args (module);
  gum_v8_invocation_args_reset (args, ic);
  auto args_object = Local<Object>::New (isolate, *args->object);

  Local<Value> argv[] = { args_object };
  auto result = on_hit->Call (context, recv, G_N_ELEMENTS (argv), argv);
  if (result.IsEmpty ())
    scope.ProcessAnyPendingException ();

  gum_v8_invocation_args_reset (args, NULL);
  gum_v8_interceptor_release_invocation_args (module, args);

  _gum_v8_invocation_context_reset (jic, NULL);
  _gum_v8_interceptor_release_invocation_context (module, jic);
}

static void
gum_v8_c_call_listener_class_init (GumV8CCallListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_c_call_listener_dispose;
}

static void
gum_v8_c_call_listener_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_c_call_listener_on_enter;
  iface->on_leave = gum_v8_c_call_listener_on_leave;
}

static void
gum_v8_c_call_listener_init (GumV8CCallListener * self)
{
}

static void
gum_v8_c_call_listener_dispose (GObject * object)
{
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_c_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_c_call_listener_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * ic)
{
  auto self = GUM_V8_C_CALL_LISTENER_CAST (listener);

  if (self->on_enter != NULL)
    self->on_enter (ic);
}

static void
gum_v8_c_call_listener_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * ic)
{
  auto self = GUM_V8_C_CALL_LISTENER_CAST (listener);

  if (self->on_leave != NULL)
    self->on_leave (ic);
}

static void
gum_v8_c_probe_listener_class_init (GumV8CProbeListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_c_probe_listener_dispose;
}

static void
gum_v8_c_probe_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_c_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_v8_c_probe_listener_init (GumV8CProbeListener * self)
{
}

static void
gum_v8_c_probe_listener_dispose (GObject * object)
{
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_c_probe_listener_parent_class)->dispose (object);
}

static void
gum_v8_c_probe_listener_on_enter (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  GUM_V8_C_PROBE_LISTENER_CAST (listener)->on_hit (ic);
}

static GumV8InvocationContext *
gum_v8_invocation_context_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto jic = g_slice_new (GumV8InvocationContext);

  auto invocation_context_value = Local<Object>::New (isolate,
      *parent->invocation_context_value);
  auto object = invocation_context_value->Clone ();
  object->SetAlignedPointerInInternalField (0, jic);
  jic->object = new Global<Object> (isolate, object);
  jic->handle = NULL;
  jic->cpu_context = nullptr;
  jic->dirty = FALSE;

  jic->module = parent;

  return jic;
}

static void
gum_v8_invocation_context_release_persistent (GumV8InvocationContext * self)
{
  self->object->SetWeak (self, gum_v8_invocation_context_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_context_values, self);
}

static void
gum_v8_invocation_context_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationContext> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_context_values, self);
}

static void
gum_v8_invocation_context_free (GumV8InvocationContext * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationContext, self);
}

void
_gum_v8_invocation_context_reset (GumV8InvocationContext * self,
                                  GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != nullptr)
  {
    _gum_v8_cpu_context_free_later (self->cpu_context, self->module->core);
    self->cpu_context = nullptr;
  }
}

static gboolean
gum_v8_invocation_context_check_valid (GumV8InvocationContext * self,
                                       Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw (isolate, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_return_address,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  auto return_address =
      gum_invocation_context_get_return_address (self->handle);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (return_address, core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_cpu_context,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  auto context = self->cpu_context;
  if (context == nullptr)
  {
    context = new Global<Object> (isolate,
        _gum_v8_cpu_context_new_mutable (self->handle->cpu_context, core));
    self->cpu_context = context;
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_system_error,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (self->handle->system_error);
}

GUMJS_DEFINE_CLASS_SETTER (gumjs_invocation_context_set_system_error,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  gint system_error;
  if (!_gum_v8_int_get (value, &system_error, core))
    return;

  self->handle->system_error = system_error;
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_thread_id,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_depth,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      (int32_t) gum_invocation_context_get_depth (self->handle));
}

static void
gumjs_invocation_context_set_property (Local<Name> property,
                                       Local<Value> value,
                                       const PropertyCallbackInfo<Value> & info)
{
  auto holder = info.Holder ();
  auto self =
      (GumV8InvocationContext *) holder->GetAlignedPointerFromInternalField (0);
  auto module =
      (GumV8Interceptor *) info.Data ().As<External> ()->Value ();

  if (holder == *module->cached_invocation_context->object)
  {
    module->cached_invocation_context =
        gum_v8_invocation_context_new_persistent (module);
    module->cached_invocation_context_in_use = FALSE;
  }

  self->dirty = TRUE;
}

static GumV8InvocationArgs *
gum_v8_invocation_args_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto args = g_slice_new (GumV8InvocationArgs);

  auto invocation_args_value = Local<Object>::New (isolate,
      *parent->invocation_args_value);
  auto object = invocation_args_value->Clone ();
  object->SetAlignedPointerInInternalField (0, args);
  args->object = new Global<Object> (isolate, object);
  args->ic = NULL;

  args->module = parent;

  return args;
}

static void
gum_v8_invocation_args_release_persistent (GumV8InvocationArgs * self)
{
  self->object->SetWeak (self, gum_v8_invocation_args_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_args_values, self);
}

static void
gum_v8_invocation_args_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationArgs> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_args_values, self);
}

static void
gum_v8_invocation_args_free (GumV8InvocationArgs * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationArgs, self);
}

static void
gum_v8_invocation_args_reset (GumV8InvocationArgs * self,
                              GumInvocationContext * ic)
{
  self->ic = ic;
}

template<typename T>
static GumV8InvocationArgs *
gum_v8_invocation_args_get (const PropertyCallbackInfo<T> & info)
{
  return (GumV8InvocationArgs *)
      info.Holder ()->GetAlignedPointerFromInternalField (0);
}

static void
gumjs_invocation_args_get_nth (uint32_t index,
                               const PropertyCallbackInfo<Value> & info)
{
  auto self = gum_v8_invocation_args_get (info);
  auto core = self->module->core;

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      gum_invocation_context_get_nth_argument (self->ic, index), core));
}

static void
gumjs_invocation_args_set_nth (uint32_t index,
                               Local<Value> value,
                               const PropertyCallbackInfo<Value> & info)
{
  auto self = gum_v8_invocation_args_get (info);
  auto core = self->module->core;

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (value);

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, core))
    return;

  gum_invocation_context_replace_nth_argument (self->ic, index, raw_value);
}

static GumV8InvocationReturnValue *
gum_v8_invocation_return_value_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto retval = g_slice_new (GumV8InvocationReturnValue);

  auto template_object = Local<Object>::New (isolate,
      *parent->invocation_return_value);
  auto object = template_object->Clone ();
  object->SetAlignedPointerInInternalField (1, retval);
  retval->object = new Global<Object> (isolate, object);
  retval->ic = NULL;

  retval->module = parent;

  return retval;
}

static void
gum_v8_invocation_return_value_release_persistent (
    GumV8InvocationReturnValue * self)
{
  self->object->SetWeak (self, gum_v8_invocation_return_value_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_return_values, self);
}

static void
gum_v8_invocation_return_value_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationReturnValue> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_return_values, self);
}

static void
gum_v8_invocation_return_value_free (GumV8InvocationReturnValue * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationReturnValue, self);
}

static void
gum_v8_invocation_return_value_reset (GumV8InvocationReturnValue * self,
                                      GumInvocationContext * ic)
{
  self->ic = ic;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  auto wrapper = info.Holder ();
  auto self = (GumV8InvocationReturnValue *)
      wrapper->GetAlignedPointerFromInternalField (1);

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  gpointer value;
  if (!_gum_v8_args_parse (args, "p~", &value))
    return;

  wrapper->SetInternalField (0,
      BigInt::NewFromUnsigned (isolate, GPOINTER_TO_SIZE (value)));

  gum_invocation_context_replace_return_value (self->ic, value);
}

GumV8InvocationContext *
_gum_v8_interceptor_obtain_invocation_context (GumV8Interceptor * self)
{
  GumV8InvocationContext * jic;

  if (!self->cached_invocation_context_in_use)
  {
    jic = self->cached_invocation_context;
    self->cached_invocation_context_in_use = TRUE;
  }
  else
  {
    jic = gum_v8_invocation_context_new_persistent (self);
  }

  return jic;
}

void
_gum_v8_interceptor_release_invocation_context (GumV8Interceptor * self,
                                                GumV8InvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_v8_invocation_context_release_persistent (jic);
}

static GumV8InvocationArgs *
gum_v8_interceptor_obtain_invocation_args (GumV8Interceptor * self)
{
  GumV8InvocationArgs * args;

  if (!self->cached_invocation_args_in_use)
  {
    args = self->cached_invocation_args;
    self->cached_invocation_args_in_use = TRUE;
  }
  else
  {
    args = gum_v8_invocation_args_new_persistent (self);
  }

  return args;
}

static void
gum_v8_interceptor_release_invocation_args (GumV8Interceptor * self,
                                            GumV8InvocationArgs * args)
{
  if (args == self->cached_invocation_args)
    self->cached_invocation_args_in_use = FALSE;
  else
    gum_v8_invocation_args_release_persistent (args);
}

static GumV8InvocationReturnValue *
gum_v8_interceptor_obtain_invocation_return_value (GumV8Interceptor * self)
{
  GumV8InvocationReturnValue * retval;

  if (!self->cached_invocation_return_value_in_use)
  {
    retval = self->cached_invocation_return_value;
    self->cached_invocation_return_value_in_use = TRUE;
  }
  else
  {
    retval = gum_v8_invocation_return_value_new_persistent (self);
  }

  return retval;
}

static void
gum_v8_interceptor_release_invocation_return_value (
    GumV8Interceptor * self,
    GumV8InvocationReturnValue * retval)
{
  if (retval == self->cached_invocation_return_value)
    self->cached_invocation_return_value_in_use = FALSE;
  else
    gum_v8_invocation_return_value_release_persistent (retval);
}
