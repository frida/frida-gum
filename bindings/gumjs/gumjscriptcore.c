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
GUM_DECLARE_JSC_FUNCTION (gumjs_set_interval);
GUM_DECLARE_JSC_FUNCTION (gumjs_clear_timer);
GUM_DECLARE_JSC_FUNCTION (gumjs_send);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_set_incoming_message_callback);
GUM_DECLARE_JSC_FUNCTION (gumjs_wait_for_event);

GUM_DECLARE_JSC_GETTER (gumjs_script_get_file_name);
GUM_DECLARE_JSC_GETTER (gumjs_script_get_source_map_data);

GUM_DECLARE_JSC_CONSTRUCTOR (gumjs_native_pointer_construct);

static JSValueRef gum_script_core_schedule_callback (GumScriptCore * self,
    const GumScriptArgs * args, gboolean repeat);
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
  _gumjs_object_set_function (ctx, scope, "setInterval", gumjs_set_interval);
  _gumjs_object_set_function (ctx, scope, "clearInterval", gumjs_clear_timer);
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
  return gum_script_core_schedule_callback (args->core, args, FALSE);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_interval)
{
  return gum_script_core_schedule_callback (args->core, args, TRUE);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_clear_timer)
{
  GumScriptCore * self = args->core;
  gint id;
  GumScheduledCallback * callback = NULL;
  GSList * cur;

  if (!_gumjs_args_parse (args, "i", &id))
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
  gchar * message;
  GBytes * data;

  if (!_gumjs_args_parse (args, "s|B?", &message, &data))
    return NULL;

  _gum_script_core_emit_message (args->core, message, data);

  g_bytes_unref (data);
  g_free (message);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumScriptCore * self = args->core;
  JSObjectRef callback;

  if (!_gumjs_args_parse (args, "C?", &callback))
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
  GumScriptCore * self = args->core;
  JSObjectRef callback;

  if (!_gumjs_args_parse (args, "C?", &callback))
    return NULL;

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (callback != NULL)
    self->incoming_message_sink = gum_message_sink_new (self->ctx, callback);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_FUNCTION (gumjs_wait_for_event)
{
  GumScriptCore * self = args->core;
  guint start_count;

  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->mutex);

  return JSValueMakeUndefined (ctx);
}

GUM_DEFINE_JSC_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  guint64 ptr;

  if (args->count == 0)
  {
    ptr = 0;
  }
  else
  {
    JSValueRef value = args->values[0];

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
          _gumjs_throw (ctx, exception,
              "argument is not a valid hexadecimal string");
        }
      }
      else
      {
        ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
        valid = endptr != ptr_as_string;
        if (!valid)
        {
          _gumjs_throw (ctx, exception,
              "argument is not a valid decimal string");
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

  return JSObjectMake (ctx, args->core->native_pointer, GSIZE_TO_POINTER (ptr));
}

static JSValueRef
gum_script_core_schedule_callback (GumScriptCore * self,
                                   const GumScriptArgs * args,
                                   gboolean repeat)
{
  JSObjectRef func;
  guint delay;
  gint id;
  GSource * source;
  GumScheduledCallback * callback;

  if (!_gumjs_args_parse (args, "Cu", &func, &delay))
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

  return JSValueMakeNumber (args->ctx, id);
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
