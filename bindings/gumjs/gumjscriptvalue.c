/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptvalue.h"

#define GUM_SCRIPT_MAX_ARRAY_LENGTH (1024 * 1024)

gchar *
_gumjs_string_get (JSStringRef str)
{
  gsize size;
  gchar * result;

  size = JSStringGetMaximumUTF8CStringSize (str);
  result = g_malloc (size);
  JSStringGetUTF8CString (str, result, size);

  return result;
}

gchar *
_gumjs_string_from_value (JSContextRef ctx,
                          JSValueRef value)
{
  gchar * result;
  JSStringRef str;

  str = JSValueToStringCopy (ctx, value, NULL);
  g_assert (str != NULL);
  result = _gumjs_string_get (str);
  JSStringRelease (str);

  return result;
}

JSValueRef
_gumjs_string_to_value (JSContextRef ctx,
                        const gchar * str)
{
  JSValueRef result;
  JSStringRef str_js;

  str_js = JSStringCreateWithUTF8CString (str);
  result = JSValueMakeString (ctx, str_js);
  JSStringRelease (str_js);

  return result;
}

JSValueRef
_gumjs_object_get (JSContextRef ctx,
                   JSObjectRef object,
                   const gchar * key)
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
_gumjs_object_get_uint (JSContextRef ctx,
                        JSObjectRef object,
                        const gchar * key)
{
  JSValueRef value;

  value = _gumjs_object_get (ctx, object, key);
  g_assert (JSValueIsNumber (ctx, value));

  return (guint) JSValueToNumber (ctx, value, NULL);
}

gchar *
_gumjs_object_get_string (JSContextRef ctx,
                          JSObjectRef object,
                          const gchar * key)
{
  JSValueRef value;

  value = _gumjs_object_get (ctx, object, key);
  g_assert (JSValueIsString (ctx, value));

  return _gumjs_string_from_value (ctx, value);
}

void
_gumjs_object_set (JSContextRef ctx,
                   JSObjectRef object,
                   const gchar * key,
                   JSValueRef value)
{
  JSStringRef property;

  property = JSStringCreateWithUTF8CString (key);
  JSObjectSetProperty (ctx, object, property, value,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, NULL);
  JSStringRelease (property);
}

void
_gumjs_object_set_string (JSContextRef ctx,
                          JSObjectRef object,
                          const gchar * key,
                          const gchar * value)
{
  _gumjs_object_set (ctx, object, key,
      _gumjs_string_to_value (ctx, value));
}

void
_gumjs_object_set_function (JSContextRef ctx,
                            JSObjectRef object,
                            const gchar * key,
                            JSObjectCallAsFunctionCallback callback)
{
  JSStringRef name;
  JSObjectRef func;

  name = JSStringCreateWithUTF8CString (key);
  func = JSObjectMakeFunctionWithCallback (ctx, name, callback);
  JSObjectSetProperty (ctx, object, name, func,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, NULL);
  JSStringRelease (name);
}

GBytes *
_gumjs_byte_array_get (JSContextRef ctx,
                       JSValueRef value,
                       JSValueRef * exception)
{
  GBytes * result;

  result = _gumjs_byte_array_try_get (ctx, value);
  if (result == NULL)
  {
    _gumjs_throw (ctx, exception, "unsupported data value");
    return NULL;
  }

  return result;
}

GBytes *
_gumjs_byte_array_try_get (JSContextRef ctx,
                           JSValueRef value)
{
  if (JSValueIsArray (ctx, value))
  {
    JSObjectRef array = (JSObjectRef) value;
    guint data_length, i;
    guint8 * data;
    gboolean data_valid;

    data_length = _gumjs_object_get_uint (ctx, array, "length");
    if (data_length > GUM_SCRIPT_MAX_ARRAY_LENGTH)
      return NULL;

    data = g_malloc (data_length);
    data_valid = TRUE;

    for (i = 0; i != data_length && data_valid; i++)
    {
      JSValueRef element;

      element = JSObjectGetPropertyAtIndex (ctx, array, i, NULL);
      if (JSValueIsNumber (ctx, element))
        data[i] = (guint8) JSValueToNumber (ctx, element, NULL);
      else
        data_valid = FALSE;
    }

    if (!data_valid)
    {
      g_free (data);
      return NULL;
    }

    return g_bytes_new_take (data, data_length);
  }

  return NULL;
}

gboolean
_gumjs_callback_get_opt (JSContextRef ctx,
                         JSValueRef value,
                         JSObjectRef * callback,
                         JSValueRef * exception)
{
  JSObjectRef result;

  if (!JSValueIsNull (ctx, value))
  {
    if (!JSValueIsObject (ctx, value))
      goto invalid_argument;

    result = (JSObjectRef) value;
    if (!JSObjectIsFunction (ctx, result))
      goto invalid_argument;
  }
  else
  {
    result = NULL;
  }

  *callback = result;
  return TRUE;

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "invalid argument");
    return FALSE;
  }
}

void
_gumjs_throw (JSContextRef ctx,
              JSValueRef * exception,
              const gchar * format,
              ...)
{
  va_list args;
  gchar * message;
  JSValueRef message_value;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  message_value = _gumjs_string_to_value (ctx, message);

  g_free (message);

  *exception = JSObjectMakeError (ctx, 1, &message_value, NULL);
}
