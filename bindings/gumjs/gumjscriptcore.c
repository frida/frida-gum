/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptcore.h"

static JSValueRef gum_on_set_incoming_message_callback (JSContextRef ctx,
    JSObjectRef function, JSObjectRef this_object, size_t argument_count,
    const JSValueRef arguments[], JSValueRef * exception);

static JSObjectRef gum_on_new_native_pointer (JSContextRef ctx,
    JSObjectRef constructor, size_t argument_count,
    const JSValueRef arguments[], JSValueRef * exception);

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

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->ctx = ctx;

  frida = JSObjectMake (ctx, NULL, NULL);
  _gum_script_object_set_string (frida, "version", FRIDA_VERSION, ctx);
  _gum_script_object_set (scope, "Frida", frida, ctx);

  _gum_script_object_set (scope, "global", scope, ctx);

  _gum_script_object_set_function (scope, "_setIncomingMessageCallback",
      gum_on_set_incoming_message_callback, self, ctx);

  def = kJSClassDefinitionEmpty;
  def.className = "NativePointer";
  self->native_pointer = JSClassCreate (&def);
  native_pointer_ctor = JSObjectMakeConstructor (ctx, self->native_pointer,
      gum_on_new_native_pointer);
  JSObjectSetPrivate (native_pointer_ctor, self->native_pointer);
  _gum_script_object_set (scope, "NativePointer", native_pointer_ctor, ctx);

  placeholder = JSObjectMake (ctx, NULL, NULL);
  _gum_script_object_set (scope, "Kernel", placeholder, ctx);
  _gum_script_object_set (scope, "Memory", placeholder, ctx);
}

void
_gum_script_core_realize (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_flush (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  JSClassRelease (self->native_pointer);
  self->native_pointer = NULL;

  g_object_unref (self->exceptor);
  self->exceptor = NULL;
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               GBytes * data)
{
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
}

static JSValueRef
gum_on_set_incoming_message_callback (JSContextRef ctx,
                                      JSObjectRef function,
                                      JSObjectRef this_object,
                                      size_t argument_count,
                                      const JSValueRef arguments[],
                                      JSValueRef * exception)
{
  return JSValueMakeUndefined (ctx);
}

static JSObjectRef
gum_on_new_native_pointer (JSContextRef ctx,
                           JSObjectRef constructor,
                           size_t argument_count,
                           const JSValueRef arguments[],
                           JSValueRef * exception)
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

      ptr_as_string = _gum_script_string_from_value (value, ctx);

      if (g_str_has_prefix (ptr_as_string, "0x"))
      {
        ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
        valid = endptr != ptr_as_string + 2;
        if (!valid)
        {
          _gum_script_throw (exception, ctx, "argument is not a valid "
              "hexadecimal string");
        }
      }
      else
      {
        ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
        valid = endptr != ptr_as_string;
        if (!valid)
        {
          _gum_script_throw (exception, ctx, "argument is not a valid decimal "
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
      _gum_script_throw (exception, ctx, "invalid argument");
      return NULL;
    }
  }

  return JSObjectMake (ctx, klass, GSIZE_TO_POINTER (ptr));
}

gchar *
_gum_script_string_get (JSStringRef str)
{
  gsize size;
  gchar * result;

  size = JSStringGetMaximumUTF8CStringSize (str);
  result = g_malloc (size);
  JSStringGetUTF8CString (str, result, size);

  return result;
}

gchar *
_gum_script_string_from_value (JSValueRef value,
                               JSContextRef ctx)
{
  gchar * result;
  JSStringRef str;

  str = JSValueToStringCopy (ctx, value, NULL);
  g_assert (str != NULL);
  result = _gum_script_string_get (str);
  JSStringRelease (str);

  return result;
}

JSValueRef
_gum_script_string_to_value (const gchar * str,
                             JSContextRef ctx)
{
  JSValueRef result;
  JSStringRef str_js;

  str_js = JSStringCreateWithUTF8CString (str);
  result = JSValueMakeString (ctx, str_js);
  JSStringRelease (str_js);

  return result;
}

JSValueRef
_gum_script_object_get (JSObjectRef object,
                        const gchar * key,
                        JSContextRef ctx)
{
  JSStringRef property;
  JSValueRef value;

  property = JSStringCreateWithUTF8CString (key);
  value = JSObjectGetProperty (ctx, object, property, NULL);
  g_assert (value != NULL);
  JSStringRelease (property);

  return value;
}

guint
_gum_script_object_get_uint (JSObjectRef object,
                             const gchar * key,
                             JSContextRef ctx)
{
  JSValueRef value;

  value = _gum_script_object_get (object, key, ctx);
  g_assert (JSValueIsNumber (ctx, value));

  return (guint) JSValueToNumber (ctx, value, NULL);
}

gchar *
_gum_script_object_get_string (JSObjectRef object,
                               const gchar * key,
                               JSContextRef ctx)
{
  JSValueRef value;

  value = _gum_script_object_get (object, key, ctx);
  g_assert (JSValueIsString (ctx, value));

  return _gum_script_string_from_value (value, ctx);
}

void
_gum_script_object_set (JSObjectRef object,
                        const gchar * key,
                        JSValueRef value,
                        JSContextRef ctx)
{
  JSStringRef property;

  property = JSStringCreateWithUTF8CString (key);
  JSObjectSetProperty (ctx, object, property, value,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, NULL);
  JSStringRelease (property);
}

void
_gum_script_object_set_string (JSObjectRef object,
                               const gchar * key,
                               const gchar * value,
                               JSContextRef ctx)
{
  _gum_script_object_set (object, key, _gum_script_string_to_value (value, ctx),
      ctx);
}

void
_gum_script_object_set_function (JSObjectRef object,
                                 const gchar * key,
                                 JSObjectCallAsFunctionCallback callback,
                                 gpointer data,
                                 JSContextRef ctx)
{
  JSStringRef name;
  JSObjectRef func;

  name = JSStringCreateWithUTF8CString (key);
  func = JSObjectMakeFunctionWithCallback (ctx, name, callback);
  JSObjectSetPrivate (func, data);
  JSObjectSetProperty (ctx, object, name, func,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, NULL);
  JSStringRelease (name);
}

void
_gum_script_throw (JSValueRef * exception,
                   JSContextRef ctx,
                   const gchar * format,
                   ...)
{
  va_list args;
  gchar * message;
  JSValueRef message_value;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  message_value = _gum_script_string_to_value (message, ctx);

  g_free (message);

  *exception = JSObjectMakeError (ctx, 1, &message_value, NULL);
}

void
_gum_script_panic (JSValueRef exception,
                   JSContextRef ctx)
{
  gchar * message, * stack;

  message = _gum_script_string_from_value (exception, ctx);
  stack = _gum_script_object_get_string ((JSObjectRef) exception, "stack", ctx);
  g_critical ("%s\n%s", message, stack);
  g_free (stack);
  g_free (message);

  abort ();
}
