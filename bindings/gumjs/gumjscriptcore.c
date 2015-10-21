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

struct _GumScheduledCallback
{
  gint id;
  gboolean repeat;
  JSObjectRef func;
  GSource * source;
  GumScriptCore * core;
};

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

GUM_DECLARE_JSC_FUNCTION (gumjs_set_timeout);
GUM_DECLARE_JSC_FUNCTION (gumjs_clear_timer);
GUM_DECLARE_JSC_FUNCTION (gumjs_send);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_incoming_message_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_wait_for_event);

GUM_DECLARE_JSC_GETTER (gumjs_script_get_file_name);
GUM_DECLARE_JSC_GETTER (gumjs_script_get_source_map_data);

GUM_DECLARE_JSC_CONSTRUCTOR (gumjs_native_pointer_construct);

static JSValueRef gum_script_core_schedule_callback (GumScriptCore * self,
    gsize num_args, const JSValueRef args[], gboolean repeat, JSValueRef * ex);
static void gum_script_core_add_scheduled_callback (GumScriptCore * self,
    GumScheduledCallback * callback);
static void gum_script_core_remove_scheduled_callback (GumScriptCore * self,
    GumScheduledCallback * callback);

static GumScheduledCallback * gum_scheduled_callback_new (gint id,
    JSObjectRef func, gboolean repeat, GSource * source, GumScriptCore * core);
static void gum_scheduled_callback_free (GumScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);

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

  _gumjs_object_set_function (ctx, scope, "setTimeout", gumjs_set_timeout);
  _gumjs_object_set_function (ctx, scope, "clearTimeout", gumjs_clear_timer);
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

  self->array_buffer =
      (JSObjectRef) _gumjs_object_get (ctx, scope, "ArrayBuffer");
  JSValueProtect (ctx, self->array_buffer);

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
  while (self->scheduled_callbacks != NULL)
  {
    g_source_destroy (((GumScheduledCallback *) (
        self->scheduled_callbacks->data))->source);
    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);
  }

  gum_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  JSValueUnprotect (self->ctx, self->array_buffer);
  self->array_buffer = NULL;

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

GUM_DEFINE_JSC_FUNCTION (gumjs_set_timeout)
{
  GumScriptCore * self;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  return gum_script_core_schedule_callback (self, num_args, args, FALSE, ex);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_clear_timer)
{
  GumScriptCore * self;
  gint id;
  GumScheduledCallback * callback = NULL;
  GSList * cur;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (!_gumjs_argv_parse (self, num_args, args, ex, "i", &id))
    return NULL;

  for (cur = self->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumScheduledCallback * cb = cur->data;
    if (cb->id == id)
    {
      callback = cb;
      self->scheduled_callbacks =
          g_slist_delete_link (self->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
    g_source_destroy (callback->source);

  return JSValueMakeBoolean (ctx, callback != NULL);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_send)
{
  GumScriptCore * self;
  gchar * message;
  GBytes * data;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (!_gumjs_argv_parse (self, num_args, args, ex, "s|B", &message, &data))
    return NULL;

  _gum_script_core_emit_message (self, message, data);

  g_bytes_unref (data);
  g_free (message);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (!_gumjs_argv_parse (self, num_args, args, ex, "F?", &callback))
    return NULL;

  gum_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  if (callback != NULL)
  {
    self->unhandled_exception_sink =
        gum_exception_sink_new (self->ctx, callback);
  }

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumScriptCore * self;
  JSObjectRef callback;

  self = GUM_JSC_CTX_GET_CORE (ctx);

  if (!_gumjs_argv_parse (self, num_args, args, ex, "F?", &callback))
    return NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (callback != NULL)
    self->incoming_message_sink = gum_message_sink_new (self->ctx, callback);

  return JSValueMakeUndefined (ctx);
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

  if (num_args == 0)
  {
    ptr = 0;
  }
  else
  {
    JSValueRef value = args[0];

    if (JSValueIsString (ctx, value))
    {
      gchar * ptr_as_string, * endptr;
      gboolean valid;

      if (!_gumjs_try_string_from_value (ctx, value, &ptr_as_string, ex))
        return NULL;

      if (g_str_has_prefix (ptr_as_string, "0x"))
      {
        ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
        valid = endptr != ptr_as_string + 2;
        if (!valid)
        {
          _gumjs_throw (ctx, ex, "argument is not a valid hexadecimal string");
        }
      }
      else
      {
        ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
        valid = endptr != ptr_as_string;
        if (!valid)
        {
          _gumjs_throw (ctx, ex, "argument is not a valid decimal string");
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
      _gumjs_throw (ctx, ex, "invalid argument");
      return NULL;
    }
  }

  return JSObjectMake (ctx, self->native_pointer, GSIZE_TO_POINTER (ptr));
}

static JSValueRef
gum_script_core_schedule_callback (GumScriptCore * self,
                                   gsize num_args,
                                   const JSValueRef args[],
                                   gboolean repeat,
                                   JSValueRef * ex)
{
  JSObjectRef func;
  guint delay;
  gint id;
  GSource * source;
  GumScheduledCallback * callback;

  if (!_gumjs_argv_parse (self, num_args, args, ex, "FI", &func, &delay))
    return NULL;

  id = g_atomic_int_add (&self->last_callback_id, 1) + 1;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new (delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      (GDestroyNotify) gum_scheduled_callback_free);
  gum_script_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));

  return JSValueMakeNumber (self->ctx, id);
}

static void
gum_script_core_add_scheduled_callback (GumScriptCore * self,
                                        GumScheduledCallback * callback)
{
  self->scheduled_callbacks =
      g_slist_prepend (self->scheduled_callbacks, callback);
}

static void
gum_script_core_remove_scheduled_callback (GumScriptCore * self,
                                           GumScheduledCallback * callback)
{
  self->scheduled_callbacks =
      g_slist_remove (self->scheduled_callbacks, callback);
}

static GumScheduledCallback *
gum_scheduled_callback_new (gint id,
                            JSObjectRef func,
                            gboolean repeat,
                            GSource * source,
                            GumScriptCore * core)
{
  GumScheduledCallback * callback;

  callback = g_slice_new (GumScheduledCallback);
  callback->id = id;
  JSValueProtect (core->ctx, func);
  callback->func = func;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_scheduled_callback_free (GumScheduledCallback * callback)
{
  JSValueUnprotect (callback->core->ctx, callback->func);

  g_slice_free (GumScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumScheduledCallback * self = user_data;
  GumScriptCore * core = self->core;
  GumScriptScope scope;

  _gum_script_scope_enter (&scope, self->core);
  JSObjectCallAsFunction (core->ctx, self->func, NULL, 0, NULL,
      &scope.exception);
  _gum_script_scope_leave (&scope);

  if (!self->repeat)
    gum_script_core_remove_scheduled_callback (core, self);

  return self->repeat;
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

gboolean
_gumjs_argv_parse (GumScriptCore * self,
                   gsize num_args,
                   const JSValueRef args[],
                   JSValueRef * exception,
                   const gchar * format,
                   ...)
{
  JSContextRef ctx = self->ctx;
  va_list ap;
  guint arg_index;
  const gchar * t;

  va_start (ap, format);

  for (arg_index = 0, t = format; *t != '\0'; arg_index++, t++)
  {
    JSValueRef value = args[arg_index];

    if (arg_index >= num_args)
      goto missing_argument;

    switch (*t)
    {
      case 'i':
      {
        gint i;
        if (!_gumjs_try_int_from_value (ctx, value, &i, exception))
          goto error;
        *va_arg (ap, gint *) = i;
        break;
      }
      case 'I':
      {
        guint i;
        if (!_gumjs_try_uint_from_value (ctx, value, &i, exception))
          goto error;
        *va_arg (ap, guint *) = i;
        break;
      }
      case 'F':
      {
        JSObjectRef func;
        if (!_gumjs_try_function_from_value (ctx, value, &func, exception))
          goto error;
        *va_arg (ap, JSObjectRef *) = func;
        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  va_end (ap);

  return TRUE;

missing_argument:
  {
    _gumjs_throw (ctx, exception, "missing argument");
    goto error;
  }
error:
  {
    va_end (ap);

    return FALSE;
  }
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

JSObjectRef
_gumjs_array_buffer_new (GumScriptCore * core,
                         gsize size)
{
  JSContextRef ctx = core->ctx;
  JSValueRef size_value;

  size_value = JSValueMakeNumber (ctx, size);

  return JSObjectCallAsConstructor (ctx, core->array_buffer, 1, &size_value,
      NULL);
}

gboolean
_gumjs_byte_array_try_get (GumScriptCore * core,
                           JSValueRef value,
                           GBytes ** bytes,
                           JSValueRef * exception)
{
  if (!_gumjs_byte_array_try_get_opt (core, value, bytes, exception))
    return FALSE;

  if (*bytes == NULL)
    goto byte_array_required;

  return TRUE;

byte_array_required:
  {
    _gumjs_throw (core->ctx, exception, "byte array required");
    return FALSE;
  }
}

gboolean
_gumjs_byte_array_try_get_opt (GumScriptCore * core,
                               JSValueRef value,
                               GBytes ** bytes,
                               JSValueRef * exception)
{
  JSContextRef ctx = core->ctx;
  gpointer buffer_data;
  gsize buffer_size;
  guint8 * data;

  if (_gumjs_array_buffer_try_get_data (core, value, &buffer_data, &buffer_size,
      NULL))
  {
    *bytes = g_bytes_new (buffer_data, buffer_size);
    return TRUE;
  }
  else if (JSValueIsArray (ctx, value))
  {
    JSObjectRef array = (JSObjectRef) value;
    guint data_length, i;

    if (!_gumjs_object_try_get_uint (ctx, array, "length", &data_length,
          exception))
      return FALSE;

    data = g_malloc (data_length);

    for (i = 0; i != data_length; i++)
    {
      JSValueRef element, ex = NULL;

      element = JSObjectGetPropertyAtIndex (ctx, array, i, &ex);
      if (ex != NULL)
        goto invalid_element_type;

      data[i] = (guint8) JSValueToNumber (ctx, element, &ex);
      if (ex != NULL)
        goto invalid_element_type;
    }

    *bytes = g_bytes_new_take (data, data_length);
    return TRUE;
  }
  else if (JSValueIsUndefined (ctx, value) || JSValueIsNull (ctx, value))
  {
    *bytes = NULL;
    return TRUE;
  }

  goto unsupported_data_value;

unsupported_data_value:
  {
    _gumjs_throw (ctx, exception, "unsupported data value");
    return FALSE;
  }
invalid_element_type:
  {
    g_free (data);
    _gumjs_throw (ctx, exception, "invalid element type");
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
