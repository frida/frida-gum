/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumv8scope.h"

#include <errno.h>

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

#define GUM_IL_LISTENER     0

#define GUM_IC_INVOCATION   0
#define GUM_IC_CPU          1

#define GUM_ARGS_INVOCATION 0

#define GUM_RV_VALUE        0
#define GUM_RV_INVOCATION   1

#define GUM_V8_INVOCATION_LISTENER_CAST(obj) \
    ((GumV8InvocationListener *) (obj))
#define GUM_V8_TYPE_CALL_LISTENER (gum_v8_call_listener_get_type ())
#define GUM_V8_TYPE_PROBE_LISTENER (gum_v8_probe_listener_get_type ())

using namespace v8;

typedef struct _GumV8InvocationListener GumV8InvocationListener;
typedef struct _GumV8CallListener GumV8CallListener;
typedef struct _GumV8CallListenerClass GumV8CallListenerClass;
typedef struct _GumV8ProbeListener GumV8ProbeListener;
typedef struct _GumV8ProbeListenerClass GumV8ProbeListenerClass;
typedef struct _GumV8ReplaceEntry GumV8ReplaceEntry;

struct _GumV8InvocationListener
{
  GObject parent;

  GumPersistent<Function>::type * on_enter;
  GumPersistent<Function>::type * on_leave;

  GumV8Interceptor * module;
};

struct _GumV8CallListener
{
  GumV8InvocationListener listener;
};

struct _GumV8CallListenerClass
{
  GObjectClass parent_class;
};

struct _GumV8ProbeListener
{
  GumV8InvocationListener listener;
};

struct _GumV8ProbeListenerClass
{
  GObjectClass parent_class;
};

struct _GumV8ReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumPersistent<Value>::type * replacement;
};

static gboolean gum_v8_interceptor_on_flush_timer_tick (gpointer user_data);

static void gum_v8_interceptor_on_attach (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_invocation_listener_destroy (
    GumV8InvocationListener * listener);
static void gum_v8_interceptor_on_detach_all (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_interceptor_on_replace (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_replace_entry_free (GumV8ReplaceEntry * entry);
static void gum_v8_interceptor_on_revert (
    const FunctionCallbackInfo<Value> & info);

static void gumjs_invocation_listener_on_detach (
    const FunctionCallbackInfo<Value> & info);

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

static void gumjs_invocation_context_on_get_return_address (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_context (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_system_error (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_set_system_error (
    Local<String> property, Local<Value> value,
    const PropertyCallbackInfo<void> & info);
static void gumjs_invocation_context_on_get_thread_id (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_depth (
    Local<String> property, const PropertyCallbackInfo<Value> & info);

static void gumjs_invocation_args_on_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_args_on_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static void gumjs_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info);

void
_gum_v8_interceptor_init (GumV8Interceptor * self,
                          GumV8Core * core,
                          Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_v8_invocation_listener_destroy));
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_v8_replace_entry_free));
  self->flush_timer = NULL;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> interceptor = ObjectTemplate::New (isolate);
  interceptor->Set (String::NewFromUtf8 (isolate, "_attach"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_attach,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "detachAll"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_detach_all,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "_replace"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_replace,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "revert"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_revert,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Interceptor"), interceptor);
}

void
_gum_v8_interceptor_realize (GumV8Interceptor * self)
{
  Isolate * isolate = self->core->isolate;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> listener = ObjectTemplate::New (isolate);
  listener->SetInternalFieldCount (1);
  listener->Set (String::NewFromUtf8 (isolate, "detach"),
      FunctionTemplate::New (isolate, gumjs_invocation_listener_on_detach,
      data));
  Local<Object> listener_value = listener->NewInstance ();
  listener_value->SetAlignedPointerInInternalField (GUM_IL_LISTENER, NULL);
  self->invocation_listener_value =
      new GumPersistent<Object>::type (isolate, listener_value);

  Handle<ObjectTemplate> context = ObjectTemplate::New (isolate);
  context->SetInternalFieldCount (2);
  context->SetAccessor (String::NewFromUtf8 (isolate, "returnAddress"),
      gumjs_invocation_context_on_get_return_address, NULL, data);
  context->SetAccessor (String::NewFromUtf8 (isolate, "context"),
      gumjs_invocation_context_on_get_context, NULL, data);
  context->SetAccessor (String::NewFromUtf8 (isolate, GUM_SYSTEM_ERROR_FIELD),
      gumjs_invocation_context_on_get_system_error,
      gumjs_invocation_context_on_set_system_error);
  context->SetAccessor (String::NewFromUtf8 (isolate, "threadId"),
      gumjs_invocation_context_on_get_thread_id);
  context->SetAccessor (String::NewFromUtf8 (isolate, "depth"),
      gumjs_invocation_context_on_get_depth);
  Local<Object> context_value = context->NewInstance ();
  context_value->SetAlignedPointerInInternalField (GUM_IC_CPU, NULL);
  self->invocation_context_value =
      new GumPersistent<Object>::type (isolate, context_value);

  Handle<ObjectTemplate> args = ObjectTemplate::New (isolate);
  args->SetInternalFieldCount (1);
  args->SetIndexedPropertyHandler (
      gumjs_invocation_args_on_get_nth,
      gumjs_invocation_args_on_set_nth,
      0, 0, 0,
      data);
  self->invocation_args_value =
      new GumPersistent<Object>::type (isolate, args->NewInstance ());

  Local<FunctionTemplate> return_value = FunctionTemplate::New (isolate);
  return_value->SetClassName (String::NewFromUtf8 (isolate, "ReturnValue"));
  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (isolate,
      *self->core->native_pointer));
  return_value->Inherit (native_pointer);
  return_value->PrototypeTemplate ()->Set (
      String::NewFromUtf8 (isolate, "replace"), FunctionTemplate::New (isolate,
      gumjs_invocation_return_value_on_replace, data));
  return_value->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return_value = new GumPersistent<Object>::type (isolate,
      return_value->GetFunction ()->NewInstance ());
}

void
_gum_v8_interceptor_flush (GumV8Interceptor * self)
{
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;
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
    GSource * source;

    source = g_timeout_source_new (10);
    g_source_set_callback (source, gum_v8_interceptor_on_flush_timer_tick,
        self, NULL);
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
gum_v8_interceptor_on_flush_timer_tick (gpointer user_data)
{
  GumV8Interceptor * self = (GumV8Interceptor *) user_data;
  gboolean flushed;

  flushed = gum_interceptor_flush (self->interceptor);
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

  delete self->invocation_return_value;
  self->invocation_return_value = nullptr;

  delete self->invocation_args_value;
  self->invocation_args_value = nullptr;

  delete self->invocation_context_value;
  self->invocation_context_value = nullptr;

  delete self->invocation_listener_value;
  self->invocation_listener_value = nullptr;
}

void
_gum_v8_interceptor_finalize (GumV8Interceptor * self)
{
  g_hash_table_unref (self->invocation_listeners);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

Local<Object>
_gum_v8_interceptor_create_invocation_context_object (
    GumV8Interceptor * self,
    GumInvocationContext * context)
{
  Isolate * isolate = self->core->isolate;
  Local<Object> invocation_context_value (Local<Object>::New (isolate,
      *self->invocation_context_value));
  Local<Object> result (invocation_context_value->Clone ());
  result->SetAlignedPointerInInternalField (GUM_IC_INVOCATION, context);
  return result;
}

void
_gum_v8_interceptor_detach_cpu_context (GumV8Interceptor * self,
                                        Handle<Value> invocation_context)
{
  Handle<Object> ic (invocation_context.As<Object> ());
  GumPersistent<Object>::type * cpu_context =
      static_cast<GumPersistent<Object>::type *> (
          ic->GetAlignedPointerFromInternalField (GUM_IC_CPU));
  if (cpu_context != NULL)
  {
    _gum_v8_cpu_context_free_later (cpu_context, self->core);
    ic->SetAlignedPointerInInternalField (GUM_IC_CPU, NULL);
  }
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
static void
gum_v8_interceptor_on_attach (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  GumV8InvocationListener * listener;
  Local<Value> value = info[1];
  if (value->IsFunction ())
  {
    listener = GUM_V8_INVOCATION_LISTENER_CAST (
        g_object_new (GUM_V8_TYPE_PROBE_LISTENER, NULL));

    listener->on_enter = new GumPersistent<Function>::type (isolate,
        Local<Function>::Cast (value));
  }
  else if (value->IsObject ())
  {
    Local<Function> on_enter, on_leave;

    Local<Object> callbacks = Local<Object>::Cast (value);
    if (!_gum_v8_callbacks_get_opt (callbacks, "onEnter", &on_enter, core))
      return;
    if (!_gum_v8_callbacks_get_opt (callbacks, "onLeave", &on_leave, core))
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
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Interceptor.attach: second argument must be a callbacks object or "
        "a probe function")));
    return;
  }

  listener->module = self;

  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      self->interceptor, target, GUM_INVOCATION_LISTENER (listener), NULL);

  if (attach_ret == GUM_ATTACH_OK)
  {
    Local<Object> listener_template_value (Local<Object>::New (isolate,
        *self->invocation_listener_value));
    Local<Object> listener_value (listener_template_value->Clone ());
    listener_value->SetAlignedPointerInInternalField (GUM_IL_LISTENER,
        listener);

    g_hash_table_insert (self->invocation_listeners, listener, listener);

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
      gchar * message;

      message = g_strdup_printf ("unable to intercept function at %p; "
          "please file a bug", target);
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, message)));
      g_free (message);

      break;
    }
    case GUM_ATTACH_ALREADY_ATTACHED:
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, "already attached to this function")));
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
static void
gum_v8_interceptor_on_detach_all (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());

  g_hash_table_remove_all (self->invocation_listeners);
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
static void
gum_v8_interceptor_on_replace (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  gpointer replacement;
  if (!_gum_v8_native_pointer_get (info[1], &replacement, self->core))
    return;

  GumV8ReplaceEntry * entry = g_slice_new (GumV8ReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = new GumPersistent<Value>::type (isolate, info[1]);

  GumReplaceReturn replace_ret = gum_interceptor_replace_function (
      self->interceptor, target, replacement, NULL);

  if (replace_ret == GUM_REPLACE_OK)
  {
    g_hash_table_insert (self->replacement_by_address, target, entry);
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
      gchar * message;

      message = g_strdup_printf ("unable to intercept function at %p; "
          "please file a bug", target);
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, message)));
      g_free (message);

      break;
    }
    case GUM_REPLACE_ALREADY_REPLACED:
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, "already replaced this function")));
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
static void
gum_v8_interceptor_on_revert (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  g_hash_table_remove (self->replacement_by_address, target);
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
static void
gumjs_invocation_listener_on_detach (const FunctionCallbackInfo<Value> & info)
{
  Local<Object> object = info.Holder ();
  GumV8InvocationListener * listener = GUM_V8_INVOCATION_LISTENER_CAST (
      object->GetAlignedPointerFromInternalField (GUM_IL_LISTENER));

  if (listener != NULL)
  {
    object->SetAlignedPointerInInternalField (GUM_IL_LISTENER, NULL);

    gum_v8_interceptor_detach (listener->module, listener);
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
  GumV8InvocationListener * self = GUM_V8_INVOCATION_LISTENER_CAST (listener);

  if (gum_script_backend_is_ignoring (
      gum_invocation_context_get_thread_id (ic)))
    return;

  if (self->on_enter != nullptr)
  {
    GumV8Interceptor * module = self->module;
    GumV8Core * core = module->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Function> on_enter (Local<Function>::New (isolate, *self->on_enter));

    Local<Object> receiver (
        _gum_v8_interceptor_create_invocation_context_object (module, ic));

    Local<Object> invocation_args_value (Local<Object>::New (isolate,
        *module->invocation_args_value));
    Local<Object> args (invocation_args_value->Clone ());
    args->SetAlignedPointerInInternalField (GUM_ARGS_INVOCATION, ic);
    Handle<Value> argv[] = { args };

    on_enter->Call (receiver, 1, argv);

    _gum_v8_interceptor_detach_cpu_context (module, receiver);

    if (self->on_leave != nullptr)
    {
      GumPersistent<Value>::type * persistent_receiver =
          new GumPersistent<Value>::type (isolate, receiver);
      *GUM_LINCTX_GET_FUNC_INVDATA (ic,
          GumPersistent<Value>::type *) = persistent_receiver;
    }
  }
}

static void
gum_v8_invocation_listener_on_leave (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GumV8InvocationListener * self = GUM_V8_INVOCATION_LISTENER_CAST (listener);

  if (gum_script_backend_is_ignoring (
      gum_invocation_context_get_thread_id (ic)))
    return;

  if (self->on_leave != nullptr)
  {
    GumV8Interceptor * module = self->module;
    GumV8Core * core = module->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Function> on_leave (Local<Function>::New (isolate, *self->on_leave));

    GumPersistent<Object>::type * persistent_receiver =
        (self->on_enter != nullptr)
        ? *GUM_LINCTX_GET_FUNC_INVDATA (ic, GumPersistent<Object>::type *)
        : nullptr;
    Local<Object> receiver ((persistent_receiver != nullptr)
        ? Local<Object>::New (isolate, *persistent_receiver)
        : _gum_v8_interceptor_create_invocation_context_object (module,
        ic));

    Local<Object> invocation_return_value (Local<Object>::New (isolate,
        *module->invocation_return_value));
    Local<Object> return_value (invocation_return_value->Clone ());
    return_value->SetInternalField (GUM_RV_VALUE, External::New (isolate,
        gum_invocation_context_get_return_value (ic)));
    return_value->SetAlignedPointerInInternalField (GUM_RV_INVOCATION, ic);

    Handle<Value> argv[] = { return_value };
    on_leave->Call (receiver, 1, argv);

    _gum_v8_interceptor_detach_cpu_context (module, receiver);

    delete persistent_receiver;
  }
}

static void
gum_v8_call_listener_class_init (GumV8CallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_call_listener_dispose;
}

static void
gum_v8_call_listener_iface_init (gpointer g_iface,
                                 gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

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
  GumV8InvocationListener * self = GUM_V8_INVOCATION_LISTENER_CAST (object);

  gum_v8_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_v8_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_probe_listener_class_init (GumV8ProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_probe_listener_dispose;
}

static void
gum_v8_probe_listener_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

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
  GumV8InvocationListener * self = GUM_V8_INVOCATION_LISTENER_CAST (object);

  gum_v8_invocation_listener_dispose (self);

  G_OBJECT_CLASS (gum_v8_probe_listener_parent_class)->dispose (object);
}

static void
gumjs_invocation_context_on_get_return_address (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  gpointer return_address = gum_invocation_context_get_return_address (context);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (return_address, self->core));
}

static void
gumjs_invocation_context_on_get_context (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Local<Object> instance = info.Holder ();
  Isolate * isolate = info.GetIsolate ();

  (void) property;

  GumPersistent<Object>::type * context =
      static_cast<GumPersistent<Object>::type *> (
          instance->GetAlignedPointerFromInternalField (GUM_IC_CPU));
  if (context == NULL)
  {
    GumInvocationContext * ic = static_cast<GumInvocationContext *> (
        instance->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
    context = new GumPersistent<Object>::type (isolate,
        _gum_v8_cpu_context_new (ic->cpu_context, self->core));
    instance->SetAlignedPointerInInternalField (GUM_IC_CPU, context);
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

static void
gumjs_invocation_context_on_get_system_error (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  info.GetReturnValue ().Set (context->system_error);
}

static void
gumjs_invocation_context_on_set_system_error (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  context->system_error = value->Int32Value ();
}

static void
gumjs_invocation_context_on_get_thread_id (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  info.GetReturnValue ().Set (gum_invocation_context_get_thread_id (context));
}

static void
gumjs_invocation_context_on_get_depth (Local<String> property,
                                       const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  info.GetReturnValue ().Set (
      static_cast<int32_t> (gum_invocation_context_get_depth (context)));
}

static void
gumjs_invocation_args_on_get_nth (uint32_t index,
                                  const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_ARGS_INVOCATION));
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      gum_invocation_context_get_nth_argument (ctx, index), self->core));
}

static void
gumjs_invocation_args_on_set_nth (uint32_t index,
                                  Local<Value> value,
                                  const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_ARGS_INVOCATION));

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, self->core))
    return;

  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);
}

static void
gumjs_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Local<Object> holder (info.Holder ());
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      holder->GetAlignedPointerFromInternalField (GUM_RV_INVOCATION));
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected an argument")));
    return;
  }

  gpointer value;
  if (!_gum_v8_native_pointer_parse (info[0], &value, self->core))
    return;
  gum_invocation_context_replace_return_value (context, value);
  holder->SetInternalField (GUM_RV_VALUE,
      External::New (info.GetIsolate (), value));
}
