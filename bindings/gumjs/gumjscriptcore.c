/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptcore.h"

#include "gumjscriptmacros.h"
#include "gumjscriptvalue.h"

#define GUM_SCRIPT_CORE_LOCK(core)   (g_mutex_lock (&(core)->mutex))
#define GUM_SCRIPT_CORE_UNLOCK(core) (g_mutex_unlock (&(core)->mutex))

struct _GumExceptionSink
{
  JSContextRef ctx;
  JSObjectRef callback;
};

struct _GumMessageSink
{
  JSContextRef ctx;
  JSObjectRef callback;
};

GUM_DECLARE_JSC_FUNCTION (gum_script_core_send);
GUM_DECLARE_JSC_FUNCTION (gum_script_core_set_unhandled_exception_callback);
GUM_DECLARE_JSC_FUNCTION (gum_script_core_set_incoming_message_callback);
GUM_DECLARE_JSC_FUNCTION (gum_script_core_wait_for_event);

GUM_DECLARE_JSC_GETTER (gum_script_get_file_name);
GUM_DECLARE_JSC_GETTER (gum_script_get_source_map_data);

GUM_DECLARE_JSC_CONSTRUCTOR (gum_native_pointer_construct);

static GumExceptionSink * gum_exception_sink_new (JSContextRef ctx,
    JSObjectRef callback);
static void gum_exception_sink_free (GumExceptionSink * sink);
static void gum_exception_sink_handle_exception (GumExceptionSink * self,
    JSValueRef exception);

static GumMessageSink * gum_message_sink_new (JSContextRef ctx,
    JSObjectRef callback);
static void gum_message_sink_free (GumMessageSink * sink);
static void gum_message_sink_handle_message (GumMessageSink * self,
    const gchar * message, JSValueRef * exception);

static const JSPropertyAttributes gum_prop_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticValue gum_script_values[] =
{
  { "fileName", gum_script_get_file_name, NULL, gum_prop_attrs },
  { "_sourceMapData", gum_script_get_source_map_data, NULL, gum_prop_attrs },
  { NULL, NULL, NULL, 0 }
};

void
_gum_script_core_init (GumScriptCore * self,
                       GumScript * script,
                       GumScriptCoreMessageEmitter message_emitter,
                       GumScriptScheduler * scheduler,
                       JSContextRef ctx,
                       JSObjectRef scope)
{
  JSClassDefinition def;
  JSObjectRef frida, native_pointer_ctor, placeholder;
  JSClassRef klass;
  JSValueRef obj;

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->ctx = ctx;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->event_cond);

  JSObjectSetPrivate (scope, self);

  _gum_script_object_set (ctx, scope, "global", scope);

  frida = JSObjectMake (ctx, NULL, NULL);
  _gum_script_object_set_string (ctx, frida, "version", FRIDA_VERSION);
  _gum_script_object_set (ctx, scope, "Frida", frida);

  def = kJSClassDefinitionEmpty;
  def.className = "Script";
  def.staticValues = gum_script_values;
  klass = JSClassCreate (&def);
  obj = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gum_script_object_set (ctx, scope, "Script", obj);

  _gum_script_object_set_function (ctx, scope, "_send", gum_script_core_send);
  _gum_script_object_set_function (ctx, scope, "_setUnhandledExceptionCallback",
      gum_script_core_set_unhandled_exception_callback);
  _gum_script_object_set_function (ctx, scope, "_setIncomingMessageCallback",
      gum_script_core_set_incoming_message_callback);
  _gum_script_object_set_function (ctx, scope, "_waitForEvent",
      gum_script_core_wait_for_event);

  def = kJSClassDefinitionEmpty;
  def.className = "NativePointer";
  self->native_pointer = JSClassCreate (&def);
  native_pointer_ctor = JSObjectMakeConstructor (ctx, self->native_pointer,
      gum_native_pointer_construct);
  JSObjectSetPrivate (native_pointer_ctor, self->native_pointer);
  _gum_script_object_set (ctx, scope, "NativePointer", native_pointer_ctor);

  placeholder = JSObjectMake (ctx, NULL, NULL);
  _gum_script_object_set (ctx, scope, "Kernel", placeholder);
  _gum_script_object_set (ctx, scope, "Memory", placeholder);
}

void
_gum_script_core_flush (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  gum_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  JSClassRelease (self->native_pointer);
  self->native_pointer = NULL;

  g_object_unref (self->exceptor);
  self->exceptor = NULL;
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  g_mutex_clear (&self->mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               GBytes * data)
{
  self->message_emitter (self->script, message, data);
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
  if (self->incoming_message_sink != NULL)
  {
    GumScriptScope scope;

    _gum_script_scope_enter (&scope, self);

    gum_message_sink_handle_message (self->incoming_message_sink, message,
        &scope.exception);

    _gum_script_scope_leave (&scope);

    GUM_SCRIPT_CORE_LOCK (self);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    GUM_SCRIPT_CORE_UNLOCK (self);
  }
}

void
_gum_script_scope_enter (GumScriptScope * self,
                         GumScriptCore * core)
{
  self->core = core;
  self->exception = NULL;

  GUM_SCRIPT_CORE_LOCK (core);
}

void
_gum_script_scope_leave (GumScriptScope * self)
{
  GumScriptCore * core = self->core;

  if (self->exception != NULL && core->unhandled_exception_sink != NULL)
  {
    gum_exception_sink_handle_exception (core->unhandled_exception_sink,
        self->exception);
  }

  GUM_SCRIPT_CORE_UNLOCK (self->core);
}

GUM_DEFINE_JSC_GETTER (gum_script_get_file_name)
{
  return JSValueMakeNull (ctx);
}

GUM_DEFINE_JSC_GETTER (gum_script_get_source_map_data)
{
  return JSValueMakeNull (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gum_script_core_send)
{
  GumScriptCore * self;
  JSValueRef message_value;
  gchar * message;
  GBytes * data = NULL;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count == 0)
    goto invalid_argument;

  message_value = arguments[0];
  if (!JSValueIsString (ctx, message_value))
    goto invalid_argument;

  if (argument_count >= 2)
  {
    JSValueRef data_value;

    data_value = arguments[1];
    if (!JSValueIsUndefined (ctx, data_value) &&
        !JSValueIsNull (ctx, data_value))
    {
      data = _gum_script_byte_array_get (ctx, data_value, exception);
      if (data == NULL)
        return NULL;
    }
  }

  message = _gum_script_string_from_value (ctx, message_value);

  _gum_script_core_emit_message (self, message, data);

  g_free (message);

  return JSValueMakeUndefined (ctx);

invalid_argument:
  {
    _gum_script_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

GUM_DEFINE_JSC_FUNCTION (gum_script_core_set_unhandled_exception_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count == 0)
    goto invalid_argument;

  if (!_gum_script_callback_get_opt (ctx, arguments[0], &callback, exception))
    return NULL;

  gum_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  if (callback != NULL)
  {
    self->unhandled_exception_sink =
        gum_exception_sink_new (self->ctx, callback);
  }

  return JSValueMakeUndefined (ctx);

invalid_argument:
  {
    _gum_script_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

GUM_DEFINE_JSC_FUNCTION (gum_script_core_set_incoming_message_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count == 0)
    goto invalid_argument;

  if (!_gum_script_callback_get_opt (ctx, arguments[0], &callback, exception))
    return NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (callback != NULL)
    self->incoming_message_sink = gum_message_sink_new (self->ctx, callback);

  return JSValueMakeUndefined (ctx);

invalid_argument:
  {
    _gum_script_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

GUM_DEFINE_JSC_FUNCTION (gum_script_core_wait_for_event)
{
  GumScriptCore * self;
  guint start_count;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->mutex);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_CONSTRUCTOR (gum_native_pointer_construct)
{
  JSClassRef klass;
  guint64 ptr;

  klass = (JSClassRef) JSObjectGetPrivate (constructor);

  if (argument_count == 0)
  {
    ptr = 0;
  }
  else
  {
    JSValueRef value = arguments[0];

    if (JSValueIsString (ctx, value))
    {
      gchar * ptr_as_string, * endptr;
      gboolean valid;

      ptr_as_string = _gum_script_string_from_value (ctx, value);

      if (g_str_has_prefix (ptr_as_string, "0x"))
      {
        ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
        valid = endptr != ptr_as_string + 2;
        if (!valid)
        {
          _gum_script_throw (ctx, exception, "argument is not a valid "
              "hexadecimal string");
        }
      }
      else
      {
        ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
        valid = endptr != ptr_as_string;
        if (!valid)
        {
          _gum_script_throw (ctx, exception, "argument is not a valid decimal "
              "string");
        }
      }

      g_free (ptr_as_string);

      if (!valid)
        return NULL;
    }
    else if (JSValueIsNumber (ctx, value))
    {
      ptr = (guint64) JSValueToNumber (ctx, value, NULL);
    }
    else
    {
      _gum_script_throw (ctx, exception, "invalid argument");
      return NULL;
    }
  }

  return JSObjectMake (ctx, klass, GSIZE_TO_POINTER (ptr));
}

static GumExceptionSink *
gum_exception_sink_new (JSContextRef ctx,
                        JSObjectRef callback)
{
  GumExceptionSink * sink;

  sink = g_slice_new (GumExceptionSink);
  sink->ctx = ctx;
  JSValueProtect (ctx, callback);
  sink->callback = callback;

  return sink;
}

static void
gum_exception_sink_free (GumExceptionSink * sink)
{
  if (sink == NULL)
    return;

  JSValueUnprotect (sink->ctx, sink->callback);

  g_slice_free (GumExceptionSink, sink);
}

static void
gum_exception_sink_handle_exception (GumExceptionSink * self,
                                     JSValueRef exception)
{
  JSObjectCallAsFunction (self->ctx, self->callback, NULL, 1, &exception, NULL);
}

static GumMessageSink *
gum_message_sink_new (JSContextRef ctx,
                      JSObjectRef callback)
{
  GumMessageSink * sink;

  sink = g_slice_new (GumMessageSink);
  sink->ctx = ctx;
  JSValueProtect (ctx, callback);
  sink->callback = callback;

  return sink;
}

static void
gum_message_sink_free (GumMessageSink * sink)
{
  if (sink == NULL)
    return;

  JSValueUnprotect (sink->ctx, sink->callback);

  g_slice_free (GumMessageSink, sink);
}

static void
gum_message_sink_handle_message (GumMessageSink * self,
                                 const gchar * message,
                                 JSValueRef * exception)
{
  JSValueRef message_value;

  message_value = _gum_script_string_to_value (self->ctx, message);
  JSObjectCallAsFunction (self->ctx, self->callback, NULL, 1, &message_value,
      exception);
}

void
_gum_script_panic (JSValueRef exception,
                   JSContextRef ctx)
{
  gchar * message, * stack;

  message = _gum_script_string_from_value (ctx, exception);
  stack = _gum_script_object_get_string (ctx, (JSObjectRef) exception, "stack");
  g_critical ("%s\n%s", message, stack);
  g_free (stack);
  g_free (message);

  abort ();
}
