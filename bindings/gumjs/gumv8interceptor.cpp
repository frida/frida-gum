/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <errno.h>

#define GUMJS_MODULE_NAME Interceptor

#define GUM_V8_INVOCATION_LISTENER_CAST(obj) \
    ((GumV8InvocationListener *) (obj))
#define GUM_V8_TYPE_CALL_LISTENER (gum_v8_call_listener_get_type ())
#define GUM_V8_TYPE_PROBE_LISTENER (gum_v8_probe_listener_get_type ())

using namespace v8;

struct GumV8InvocationListener
{
  GObject parent;

  GumPersistent<Function>::type * on_enter;
  GumPersistent<Function>::type * on_leave;

  GumV8Interceptor * module;
};

struct GumV8CallListener
{
  GumV8InvocationListener listener;
};

struct GumV8CallListenerClass
{
  GObjectClass parent_class;
};

struct GumV8ProbeListener
{
  GumV8InvocationListener listener;
};

struct GumV8ProbeListenerClass
{
  GObjectClass parent_class;
};

struct GumV8InvocationState
{
  GumV8InvocationContext * jic;
};

struct GumV8InvocationArgs
{
  GumPersistent<v8::Object>::type * object;
  GumInvocationContext * ic;

  GumV8Core * core;
};

struct GumV8InvocationReturnValue
{
  GumPersistent<v8::Object>::type * object;
  GumInvocationContext * ic;

  GumV8Core * core;
};

struct GumV8ReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumPersistent<Value>::type * replacement;
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

static void gum_v8_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_call_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumV8CallListener,
                        gum_v8_call_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_call_listener_iface_init))

static void gum_v8_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_probe_listener_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumV8ProbeListener,
                        gum_v8_probe_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_probe_listener_iface_init))

static GumV8InvocationContext * gum_v8_invocation_context_new (
    GumV8Interceptor * parent);
static void gum_v8_invocation_context_release (GumV8InvocationContext * self);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
static void gumjs_invocation_context_set_property (Local<Name> property,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationArgs * gum_v8_invocation_args_new (
    GumV8Interceptor * parent);
static void gum_v8_invocation_args_release (GumV8InvocationArgs * self);
static void gum_v8_invocation_args_reset (GumV8InvocationArgs * self,
    GumInvocationContext * ic);
static void gumjs_invocation_args_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_args_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationReturnValue * gum_v8_invocation_return_value_new (
    GumV8Interceptor * parent);
static void gum_v8_invocation_return_value_release (
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
                          Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_listener_destroy);
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
  self->invocation_listener =
      new GumPersistent<FunctionTemplate>::type (isolate, listener);

  auto ic = _gum_v8_create_class ("InvocationContext", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (ic, gumjs_invocation_context_values, module, isolate);
  NamedPropertyHandlerConfiguration ic_access;
  ic_access.setter = gumjs_invocation_context_set_property;
  ic_access.data = module;
  ic_access.flags = PropertyHandlerFlags::kNonMasking;
  ic->InstanceTemplate ()->SetHandler (ic_access);
  self->invocation_context =
      new GumPersistent<FunctionTemplate>::type (isolate, ic);

  auto ia = _gum_v8_create_class ("InvocationArgs", nullptr, scope, module,
      isolate);
  ia->InstanceTemplate ()->SetIndexedPropertyHandler (
      gumjs_invocation_args_get_nth, gumjs_invocation_args_set_nth, nullptr,
      nullptr, nullptr, module);
  self->invocation_args =
      new GumPersistent<FunctionTemplate>::type (isolate, ia);

  auto ir = _gum_v8_create_class ("InvocationReturnValue", nullptr, scope,
      module, isolate);
  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  ir->Inherit (native_pointer);
  _gum_v8_class_add (ir, gumjs_invocation_return_value_functions, module,
      isolate);
  ir->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return =
      new GumPersistent<FunctionTemplate>::type (isolate, ir);
}

void
_gum_v8_interceptor_realize (GumV8Interceptor * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto listener = Local<FunctionTemplate>::New (isolate,
      *self->invocation_listener);
  auto listener_value = listener->GetFunction ()->NewInstance (context,
      0, nullptr).ToLocalChecked ();
  self->invocation_listener_value =
      new GumPersistent<Object>::type (isolate, listener_value);

  auto ic = Local<FunctionTemplate>::New (isolate, *self->invocation_context);
  auto ic_value =
      ic->GetFunction ()->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_context_value =
      new GumPersistent<Object>::type (isolate, ic_value);

  auto ia = Local<FunctionTemplate>::New (isolate, *self->invocation_args);
  auto ia_value =
      ia->GetFunction ()->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_args_value =
      new GumPersistent<Object>::type (isolate, ia_value);

  auto ir = Local<FunctionTemplate>::New (isolate, *self->invocation_return);
  auto ir_value =
      ir->GetFunction ()->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_return_value = new GumPersistent<Object>::type (isolate,
      ir_value);

  self->cached_invocation_context = gum_v8_invocation_context_new (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args = gum_v8_invocation_args_new (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_return_value = gum_v8_invocation_return_value_new (
      self);
  self->cached_invocation_return_value_in_use = FALSE;
}

void
_gum_v8_interceptor_flush (GumV8Interceptor * self)
{
  auto core = self->core;
  auto isolate = core->isolate;
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  isolate->Exit ();
  {
    Unlocker ul (isolate);

    gum_interceptor_end_transaction (self->interceptor);
    flushed = gum_interceptor_flush (self->interceptor);
    gum_interceptor_begin_transaction (self->interceptor);
  }
  isolate->Enter ();

  if (!flushed && self->flush_timer == NULL)
  {
    auto source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_interceptor_on_flush_timer_tick, self, NULL);
    self->flush_timer = source;

    _gum_v8_core_pin (core);

    isolate->Exit ();
    {
      Unlocker ul (isolate);

      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
      g_source_unref (source);
    }
    isolate->Enter ();
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

  gum_v8_invocation_context_release (self->cached_invocation_context);
  gum_v8_invocation_args_release (self->cached_invocation_args);
  gum_v8_invocation_return_value_release (self->cached_invocation_return_value);
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
}

void
_gum_v8_interceptor_finalize (GumV8Interceptor * self)
{
  g_hash_table_unref (self->invocation_listeners);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

/*
 * Prototype:
 * [PRIVATE] Interceptor._attach(target, callbacks|probe)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  gpointer target;
  Local<Function> on_enter, on_leave;
  GumV8InvocationListener * listener;

  if (info.Length () >= 2 && info[1]->IsFunction ())
  {
    if (!_gum_v8_args_parse (args, "pF", &target, &on_enter))
      return;

    listener = GUM_V8_INVOCATION_LISTENER_CAST (
        g_object_new (GUM_V8_TYPE_PROBE_LISTENER, NULL));

    listener->on_enter = new GumPersistent<Function>::type (isolate, on_enter);
  }
  else
  {
    if (!_gum_v8_args_parse (args, "pF{onEnter?,onLeave?}", &target, &on_enter,
        &on_leave))
      return;

    listener = GUM_V8_INVOCATION_LISTENER_CAST (
        g_object_new (GUM_V8_TYPE_CALL_LISTENER, NULL));

    if (!on_enter.IsEmpty ())
    {
      listener->on_enter =
          new GumPersistent<Function>::type (isolate, on_enter);
    }

    if (!on_leave.IsEmpty ())
    {
      listener->on_leave =
          new GumPersistent<Function>::type (isolate, on_leave);
    }
  }

  listener->module = module;

  auto attach_ret = gum_interceptor_attach_listener (module->interceptor,
      target, GUM_INVOCATION_LISTENER (listener), NULL);

  if (attach_ret == GUM_ATTACH_OK)
  {
    auto listener_template_value (Local<Object>::New (isolate,
        *module->invocation_listener_value));
    auto listener_value (listener_template_value->Clone ());
    listener_value->SetAlignedPointerInInternalField (0, listener);

    g_hash_table_insert (module->invocation_listeners, listener, listener);

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
  }
}

static void
gum_v8_invocation_listener_destroy (GumV8InvocationListener * listener)
{
  gum_interceptor_detach_listener (listener->module->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_v8_interceptor_detach (GumV8Interceptor * self,
                           GumV8InvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

/*
 * Prototype:
 * Interceptor.detachAll()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  g_hash_table_remove_all (module->invocation_listeners);
}

/*
 * Prototype:
 * [PRIVATE] Interceptor._replace(target, replacement)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  gpointer target, replacement;
  if (!_gum_v8_args_parse (args, "pp", &target, &replacement))
    return;
  auto replacement_value = info[1];

  auto entry = g_slice_new (GumV8ReplaceEntry);
  entry->interceptor = module->interceptor;
  entry->target = target;
  entry->replacement = new GumPersistent<Value>::type (isolate,
      replacement_value);

  auto replace_ret = gum_interceptor_replace_function (module->interceptor,
      target, replacement, NULL);

  if (replace_ret == GUM_REPLACE_OK)
  {
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
  }
}

static void
gum_v8_replace_entry_free (GumV8ReplaceEntry * entry)
{
  gum_interceptor_revert_function (entry->interceptor, entry->target);

  delete entry->replacement;

  g_slice_free (GumV8ReplaceEntry, entry);
}

/*
 * Prototype:
 * Interceptor.revert(target)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  gpointer target;
  if (!_gum_v8_args_parse (args, "p", &target))
    return;

  g_hash_table_remove (module->replacement_by_address, target);
}

/*
 * Prototype:
 * Interceptor.flush()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  auto interceptor = module->interceptor;

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);
}

/*
 * Prototype:
 * InvocationListener.detach()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
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
gum_v8_invocation_listener_dispose (GumV8InvocationListener * self)
{
  ScriptScope scope (self->module->core->script);

  delete self->on_enter;
  self->on_enter = nullptr;

  delete self->on_leave;
  self->on_leave = nullptr;
}

static void
gum_v8_invocation_listener_on_enter (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  auto self = GUM_V8_INVOCATION_LISTENER_CAST (listener);
  auto state = GUM_LINCTX_GET_FUNC_INVDATA (ic, GumV8InvocationState);

  if (self->on_enter != nullptr)
  {
    auto module = self->module;
    auto core = module->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;

    auto on_enter = Local<Function>::New (isolate, *self->on_enter);

    auto jic = _gum_v8_interceptor_obtain_invocation_context (module);
    _gum_v8_invocation_context_reset (jic, ic);
    auto receiver = Local<Object>::New (isolate, *jic->object);

    auto args = gum_v8_interceptor_obtain_invocation_args (module);
    gum_v8_invocation_args_reset (args, ic);
    auto args_object = Local<Object>::New (isolate, *args->object);

    Handle<Value> argv[] = { args_object };
    on_enter->Call (receiver, G_N_ELEMENTS (argv), argv);

    gum_v8_invocation_args_reset (args, NULL);
    gum_v8_interceptor_release_invocation_args (module, args);

    _gum_v8_invocation_context_reset (jic, NULL);
    if (self->on_leave != nullptr)
    {
      state->jic = jic;
    }
    else
    {
      _gum_v8_interceptor_release_invocation_context (module, jic);
    }
  }
}

static void
gum_v8_invocation_listener_on_leave (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  auto self = GUM_V8_INVOCATION_LISTENER_CAST (listener);

  if (self->on_leave == nullptr)
    return;

  auto state = GUM_LINCTX_GET_FUNC_INVDATA (ic, GumV8InvocationState);

  {
    auto module = self->module;
    auto core = module->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;

    auto on_leave = Local<Function>::New (isolate, *self->on_leave);

    auto jic = (self->on_enter != nullptr) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_v8_interceptor_obtain_invocation_context (module);
    }
    _gum_v8_invocation_context_reset (jic, ic);
    auto receiver = Local<Object>::New (isolate, *jic->object);

    auto retval = gum_v8_interceptor_obtain_invocation_return_value (module);
    gum_v8_invocation_return_value_reset (retval, ic);
    auto retval_object = Local<Object>::New (isolate, *retval->object);
    retval_object->SetInternalField (0, External::New (isolate,
        gum_invocation_context_get_return_value (ic)));

    Handle<Value> argv[] = { retval_object };
    on_leave->Call (receiver, G_N_ELEMENTS (argv), argv);

    gum_v8_invocation_return_value_reset (retval, NULL);
    gum_v8_interceptor_release_invocation_return_value (module, retval);

    _gum_v8_invocation_context_reset (jic, NULL);
    _gum_v8_interceptor_release_invocation_context (module, jic);
  }
}

static void
gum_v8_call_listener_class_init (GumV8CallListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_call_listener_dispose;
}

static void
gum_v8_call_listener_iface_init (gpointer g_iface,
                                 gpointer iface_data)
{
  auto iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_v8_invocation_listener_on_enter;
  iface->on_leave = gum_v8_invocation_listener_on_leave;
}

static void
gum_v8_call_listener_init (GumV8CallListener * self)
{
  (void) self;
}

static void
gum_v8_call_listener_dispose (GObject * object)
{
  auto self = GUM_V8_INVOCATION_LISTENER_CAST (object);

  gum_v8_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_v8_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_probe_listener_class_init (GumV8ProbeListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_probe_listener_dispose;
}

static void
gum_v8_probe_listener_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  auto iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_v8_invocation_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_v8_probe_listener_init (GumV8ProbeListener * self)
{
  (void) self;
}

static void
gum_v8_probe_listener_dispose (GObject * object)
{
  auto self = GUM_V8_INVOCATION_LISTENER_CAST (object);

  gum_v8_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_v8_probe_listener_parent_class)->dispose (object);
}

static GumV8InvocationContext *
gum_v8_invocation_context_new (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto jic = g_slice_new (GumV8InvocationContext);

  auto invocation_context_value = Local<Object>::New (isolate,
      *parent->invocation_context_value);
  auto object = invocation_context_value->Clone ();
  object->SetAlignedPointerInInternalField (0, jic);
  jic->object = new GumPersistent<Object>::type (isolate, object);
  jic->handle = NULL;
  jic->cpu_context = nullptr;

  jic->core = parent->core;

  return jic;
}

static void
gum_v8_invocation_context_release (GumV8InvocationContext * self)
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
    _gum_v8_cpu_context_free_later (self->cpu_context, self->core);
    self->cpu_context = nullptr;
  }
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_return_address,
                           GumV8InvocationContext)
{
  auto return_address =
      gum_invocation_context_get_return_address (self->handle);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (return_address, core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_cpu_context,
                           GumV8InvocationContext)
{
  auto context = self->cpu_context;
  if (context == nullptr)
  {
    context = new GumPersistent<Object>::type (isolate,
        _gum_v8_cpu_context_new (self->handle->cpu_context, core));
    self->cpu_context = context;
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_system_error,
                           GumV8InvocationContext)
{
  info.GetReturnValue ().Set (self->handle->system_error);
}

GUMJS_DEFINE_CLASS_SETTER (gumjs_invocation_context_set_system_error,
                           GumV8InvocationContext)
{
  gint system_error;
  if (!_gum_v8_int_get (value, &system_error, core))
    return;

  self->handle->system_error = system_error;
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_thread_id,
                           GumV8InvocationContext)
{
  info.GetReturnValue ().Set (
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_depth,
                           GumV8InvocationContext)
{
  info.GetReturnValue ().Set (
      (int32_t) gum_invocation_context_get_depth (self->handle));
}

static void
gumjs_invocation_context_set_property (Local<Name> property,
                                       Local<Value> value,
                                       const PropertyCallbackInfo<Value> & info)
{
  auto module =
      (GumV8Interceptor *) info.Data ().As<External> ()->Value ();

  (void) property;
  (void) value;

  if (info.Holder () == *module->cached_invocation_context->object)
  {
    module->cached_invocation_context = gum_v8_invocation_context_new (module);
    module->cached_invocation_context_in_use = FALSE;
  }
}

static GumV8InvocationArgs *
gum_v8_invocation_args_new (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto args = g_slice_new (GumV8InvocationArgs);

  auto invocation_args_value = Local<Object>::New (isolate,
      *parent->invocation_args_value);
  auto object = invocation_args_value->Clone ();
  object->SetAlignedPointerInInternalField (0, args);
  args->object = new GumPersistent<Object>::type (isolate, object);
  args->ic = NULL;

  args->core = parent->core;

  return args;
}

static void
gum_v8_invocation_args_release (GumV8InvocationArgs * self)
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
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      gum_invocation_context_get_nth_argument (self->ic, index), self->core));
}

static void
gumjs_invocation_args_set_nth (uint32_t index,
                               Local<Value> value,
                               const PropertyCallbackInfo<Value> & info)
{
  auto self = gum_v8_invocation_args_get (info);

  info.GetReturnValue ().Set (value);

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, self->core))
    return;

  gum_invocation_context_replace_nth_argument (self->ic, index, raw_value);
}

static GumV8InvocationReturnValue *
gum_v8_invocation_return_value_new (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto retval = g_slice_new (GumV8InvocationReturnValue);

  auto template_object = Local<Object>::New (isolate,
      *parent->invocation_return_value);
  auto object = template_object->Clone ();
  object->SetAlignedPointerInInternalField (1, retval);
  retval->object = new GumPersistent<Object>::type (isolate, object);
  retval->ic = NULL;

  retval->core = parent->core;

  return retval;
}

static void
gum_v8_invocation_return_value_release (GumV8InvocationReturnValue * self)
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

  wrapper->SetInternalField (0, External::New (isolate, value));

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
    jic = gum_v8_invocation_context_new (self);
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
    gum_v8_invocation_context_release (jic);
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
    args = gum_v8_invocation_args_new (self);
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
    gum_v8_invocation_args_release (args);
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
    retval = gum_v8_invocation_return_value_new (self);
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
    gum_v8_invocation_return_value_release (retval);
}
