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
  JSObjectRef callback;
  JSContextRef ctx;
};

struct _GumMessageSink
{
  JSObjectRef callback;
  JSContextRef ctx;
};

GUM_DECLARE_JSC_FUNCTION (gumjs_send);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_incoming_message_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_wait_for_event);

GUM_DECLARE_JSC_GETTER (gumjs_script_get_file_name);
GUM_DECLARE_JSC_GETTER (gumjs_script_get_source_map_data);

GUM_DECLARE_JSC_CONSTRUCTOR (gumjs_native_pointer_construct);

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

static const gchar * gum_exception_type_to_string (GumExceptionType type);

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticValue gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL, gumjs_attrs },
  { "_sourceMapData", gumjs_script_get_source_map_data, NULL, gumjs_attrs },
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
  GumScriptFlavor flavor;
  JSClassDefinition def;
  JSObjectRef frida;
  JSClassRef klass;
  JSValueRef obj;

  g_object_get (script, "flavor", &flavor, NULL);

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->ctx = ctx;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->event_cond);

  JSObjectSetPrivate (scope, self);

  _gumjs_object_set (ctx, scope, "global", scope);

  frida = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_string (ctx, frida, "version", FRIDA_VERSION);
  _gumjs_object_set (ctx, scope, "Frida", frida);

  def = kJSClassDefinitionEmpty;
  def.className = "Script";
  def.staticValues = gumjs_script_values;
  klass = JSClassCreate (&def);
  obj = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Script", obj);

  _gumjs_object_set_function (ctx, scope, "_send", gumjs_send);
  _gumjs_object_set_function (ctx, scope, "_setUnhandledExceptionCallback",
      gumjs_set_unhandled_exception_callback);
  _gumjs_object_set_function (ctx, scope, "_setIncomingMessageCallback",
      gumjs_set_incoming_message_callback);
  _gumjs_object_set_function (ctx, scope, "_waitForEvent",
      gumjs_wait_for_event);

  def = kJSClassDefinitionEmpty;
  def.className = "NativePointer";
  self->native_pointer = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, "NativePointer", JSObjectMakeConstructor (ctx,
      self->native_pointer, gumjs_native_pointer_construct));

  if (flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    _gumjs_object_set (ctx, scope, "Process", JSObjectMake (ctx, NULL, NULL));
    _gumjs_object_set (ctx, scope, "Module", JSObjectMake (ctx, NULL, NULL));
    _gumjs_object_set (ctx, scope, "Instruction",
        JSObjectMake (ctx, NULL, NULL));
  }
  else
  {
    _gumjs_object_set (ctx, scope, "Kernel", JSObjectMake (ctx, NULL, NULL));
  }
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
  g_print ("%s\n", message);
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

GUM_DEFINE_JSC_GETTER (gumjs_script_get_file_name)
{
  return JSValueMakeNull (ctx);
}

GUM_DEFINE_JSC_GETTER (gumjs_script_get_source_map_data)
{
  return JSValueMakeNull (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_send)
{
  GumScriptCore * self;
  JSValueRef result = NULL;
  gchar * message = NULL;
  GBytes * data = NULL;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count < 1)
    goto invalid_argument;

  if (!_gumjs_try_string_from_value (ctx, arguments[0], &message, exception))
    goto beach;

  if (argument_count >= 2)
  {
    if (!_gumjs_byte_array_try_get_opt (ctx, arguments[1], &data, exception))
      goto beach;
  }

  _gum_script_core_emit_message (self, message, data);

  result = JSValueMakeUndefined (ctx);
  goto beach;

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "invalid argument");
    goto beach;
  }
beach:
  {
    g_bytes_unref (data);
    g_free (message);

    return result;
  }
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count < 1)
    goto invalid_argument;

  if (!_gumjs_callback_try_get_opt (ctx, arguments[0], &callback, exception))
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
    _gumjs_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (argument_count < 1)
    goto invalid_argument;

  if (!_gumjs_callback_try_get_opt (ctx, arguments[0], &callback, exception))
    return NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (callback != NULL)
    self->incoming_message_sink = gum_message_sink_new (self->ctx, callback);

  return JSValueMakeUndefined (ctx);

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "invalid argument");
    return NULL;
  }
}

GUM_DEFINE_JSC_FUNCTION (gumjs_wait_for_event)
{
  GumScriptCore * self;
  guint start_count;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->mutex);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  GumScriptCore * self;
  guint64 ptr;

  self = GUM_JSC_CTX_GET_CORE (ctx);

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

      if (!_gumjs_try_string_from_value (ctx, value, &ptr_as_string, exception))
        return NULL;

      if (g_str_has_prefix (ptr_as_string, "0x"))
      {
        ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
        valid = endptr != ptr_as_string + 2;
        if (!valid)
        {
          _gumjs_throw (ctx, exception, "argument is not a valid "
              "hexadecimal string");
        }
      }
      else
      {
        ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
        valid = endptr != ptr_as_string;
        if (!valid)
        {
          _gumjs_throw (ctx, exception, "argument is not a valid decimal "
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
      _gumjs_throw (ctx, exception, "invalid argument");
      return NULL;
    }
  }

  return JSObjectMake (ctx, self->native_pointer, GSIZE_TO_POINTER (ptr));
}

static GumExceptionSink *
gum_exception_sink_new (JSContextRef ctx,
                        JSObjectRef callback)
{
  GumExceptionSink * sink;

  sink = g_slice_new (GumExceptionSink);
  JSValueProtect (ctx, callback);
  sink->callback = callback;
  sink->ctx = ctx;

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
  JSValueProtect (ctx, callback);
  sink->callback = callback;
  sink->ctx = ctx;

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

  message_value = _gumjs_string_to_value (self->ctx, message);
  JSObjectCallAsFunction (self->ctx, self->callback, NULL, 1, &message_value,
      exception);
}

JSValueRef
_gumjs_native_pointer_new (GumScriptCore * core,
                           gpointer address)
{
  return JSObjectMake (core->ctx, core->native_pointer, address);
}

gboolean
_gumjs_native_pointer_get (GumScriptCore * core,
                           JSValueRef value,
                           gpointer * target,
                           JSValueRef * exception)
{
  JSContextRef ctx = core->ctx;

  if (JSValueIsObjectOfClass (ctx, value, core->native_pointer))
  {
    *target = JSObjectGetPrivate ((JSObjectRef) value);
    return TRUE;
  }
  else
  {
    /* TODO: support object with `handle` property */
    _gumjs_throw (ctx, exception, "expected NativePointer object");
    return FALSE;
  }
}

void
_gumjs_throw_native (GumScriptCore * core,
                     GumExceptionDetails * details,
                     JSValueRef * exception)
{
  JSContextRef ctx = core->ctx;
  gchar * message;
  JSValueRef message_value;
  JSObjectRef ex;

  message = gum_exception_details_to_string (details);
  message_value = _gumjs_string_to_value (ctx, message);
  g_free (message);

  ex = JSObjectMakeError (ctx, 1, &message_value, NULL);

  _gumjs_object_set_string (ctx, ex, "type",
      gum_exception_type_to_string (details->type));
  /* TODO: fill out the other details */

  *exception = ex;
}

static const gchar *
gum_exception_type_to_string (GumExceptionType type)
{
  switch (type)
  {
    case GUM_EXCEPTION_ABORT: return "abort";
    case GUM_EXCEPTION_ACCESS_VIOLATION: return "access-violation";
    case GUM_EXCEPTION_GUARD_PAGE: return "guard-page";
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal-instruction";
    case GUM_EXCEPTION_STACK_OVERFLOW: return "stack-overflow";
    case GUM_EXCEPTION_ARITHMETIC: return "arithmetic";
    case GUM_EXCEPTION_BREAKPOINT: return "breakpoint";
    case GUM_EXCEPTION_SINGLE_STEP: return "single-step";
    case GUM_EXCEPTION_SYSTEM: return "system";
    default:
      break;
  }

  g_assert_not_reached ();
}
