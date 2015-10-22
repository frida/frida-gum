/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptvalue.h"

#include "gumjscript-priv.h"

#define GUM_SCRIPT_MAX_ARRAY_LENGTH (1024 * 1024)

static const gchar * gum_exception_type_to_string (GumExceptionType type);

gboolean
_gumjs_args_parse (const GumScriptArgs * self,
                   const gchar * format,
                   ...)
{
  JSContextRef ctx = self->ctx;
  GumScriptCore * core = self->core;
  JSValueRef * exception = self->exception;
  va_list ap;
  guint arg_index;
  const gchar * t;
  gboolean is_required;

  va_start (ap, format);

  is_required = TRUE;
  for (arg_index = 0, t = format; *t != '\0'; arg_index++, t++)
  {
    JSValueRef value;

    if (arg_index >= self->count)
    {
      if (is_required)
        goto missing_argument;
      else
        value = NULL;
    }
    else
    {
      value = self->values[arg_index];
    }

    switch (*t)
    {
      case 'i':
      {
        gint i = 0;

        if (value != NULL &&
            !_gumjs_try_int_from_value (ctx, value, &i, exception))
        {
          goto error;
        }

        *va_arg (ap, gint *) = i;

        break;
      }
      case 'u':
      {
        guint i = 0;

        if (value != NULL &&
            !_gumjs_try_uint_from_value (ctx, value, &i, exception))
        {
          goto error;
        }

        *va_arg (ap, guint *) = i;

        break;
      }
      case 'p':
      {
        gpointer ptr = NULL;

        if (value != NULL &&
            !_gumjs_native_pointer_try_get (ctx, value, core, &ptr, exception))
        {
          goto error;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 's':
      {
        gchar * str = NULL;

        if (value != NULL &&
            !_gumjs_try_string_from_value (ctx, value, &str, exception))
        {
          goto error;
        }

        *va_arg (ap, gchar **) = str;

        break;
      }
      case 'C':
      {
        JSObjectRef func;
        gboolean is_object, is_nullable;

        is_object = t[1] == '{';
        if (is_object)
          t += 2;

        if (is_object)
        {
          const gchar * next, * end, * t_end;

          do
          {
            gchar name[64];
            gsize length;

            next = strchr (t, ',');
            end = strchr (t, '}');
            t_end = (next != NULL && next < end) ? next : end;
            length = t_end - t;
            strncpy (name, t, length);

            is_nullable = name[length - 1] == '?';
            if (is_nullable)
              name[length - 1] = '\0';
            else
              name[length] = '\0';

            if (value != NULL)
            {
              if (is_nullable)
              {
                if (!_gumjs_callbacks_try_get_opt (ctx, value, name, &func,
                    exception))
                  goto error;
              }
              else
              {
                if (!_gumjs_callbacks_try_get (ctx, value, name, &func,
                    exception))
                  goto error;
              }
            }
            else
            {
              func = NULL;
            }

            *va_arg (ap, JSObjectRef *) = func;

            t = t_end + 1;
          }
          while (t_end != end);

          t--;
        }
        else
        {
          is_nullable = t[1] == '?';
          if (is_nullable)
            t++;

          if (value != NULL)
          {
            if (is_nullable)
            {
              if (!_gumjs_callback_try_get_opt (ctx, value, &func, exception))
                goto error;
            }
            else
            {
              if (!_gumjs_callback_try_get (ctx, value, &func, exception))
                goto error;
            }
          }
          else
          {
            func = NULL;
          }

          *va_arg (ap, JSObjectRef *) = func;
        }

        break;
      }
      case 'B':
      {
        GBytes * bytes;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (value != NULL)
        {
          if (is_nullable)
          {
            if (!_gumjs_byte_array_try_get_opt (ctx, value, &bytes, exception))
              goto error;
          }
          else
          {
            if (!_gumjs_byte_array_try_get (ctx, value, &bytes, exception))
              goto error;
          }
        }
        else
        {
          bytes = NULL;
        }

        *va_arg (ap, GBytes **) = bytes;

        break;
      }
      case '|':
        is_required = FALSE;
        break;
      default:
        g_printerr ("Unhandled: %c\n", *t);
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

gboolean
_gumjs_try_int_from_value (JSContextRef ctx,
                           JSValueRef value,
                           gint * i,
                           JSValueRef * exception)
{
  JSValueRef ex = NULL;
  double number;

  number = JSValueToNumber (ctx, value, &ex);
  if (ex == NULL)
    *i = (gint) number;

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;
}

gboolean
_gumjs_try_uint_from_value (JSContextRef ctx,
                            JSValueRef value,
                            guint * i,
                            JSValueRef * exception)
{
  JSValueRef ex = NULL;
  double number;

  number = JSValueToNumber (ctx, value, &ex);
  if (ex == NULL)
  {
    if (number < 0)
      goto invalid_uint;

    *i = (guint) number;
  }

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;

invalid_uint:
  {
    _gumjs_throw (ctx, exception, "expected a non-negative integer");
    return FALSE;
  }
}

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
  gchar * str;
  JSValueRef exception;

  if (!_gumjs_try_string_from_value (ctx, value, &str, &exception))
    _gumjs_panic (ctx, exception);

  return str;
}

gboolean
_gumjs_try_string_from_value (JSContextRef ctx,
                              JSValueRef value,
                              gchar ** str,
                              JSValueRef * exception)
{
  JSStringRef s;

  s = JSValueToStringCopy (ctx, value, exception);
  if (s == NULL)
    return FALSE;
  *str = _gumjs_string_get (s);
  JSStringRelease (s);

  return TRUE;
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
  JSValueRef value, exception;

  if (!_gumjs_object_try_get (ctx, object, key, &value, &exception))
    _gumjs_panic (ctx, exception);

  return value;
}

gboolean
_gumjs_object_try_get (JSContextRef ctx,
                       JSObjectRef object,
                       const gchar * key,
                       JSValueRef * value,
                       JSValueRef * exception)
{
  JSStringRef property;
  JSValueRef ex = NULL;

  property = JSStringCreateWithUTF8CString (key);
  *value = JSObjectGetProperty (ctx, object, property, &ex);
  JSStringRelease (property);

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;
}

guint
_gumjs_object_get_uint (JSContextRef ctx,
                        JSObjectRef object,
                        const gchar * key)
{
  guint value;
  JSValueRef exception;

  if (!_gumjs_object_try_get_uint (ctx, object, key, &value, &exception))
    _gumjs_panic (ctx, exception);

  return value;
}

gboolean
_gumjs_object_try_get_uint (JSContextRef ctx,
                            JSObjectRef object,
                            const gchar * key,
                            guint * value,
                            JSValueRef * exception)
{
  JSValueRef v, ex = NULL;
  double number;

  if (!_gumjs_object_try_get (ctx, object, key, &v, exception))
    return FALSE;

  if (!JSValueIsNumber (ctx, v))
    goto invalid_type;

  number = JSValueToNumber (ctx, v, &ex);
  if (ex != NULL)
    goto propagate_exception;

  *value = (guint) number;
  return TRUE;

invalid_type:
  {
    _gumjs_throw (ctx, exception, "expected '%s' to be a number", key);
    return FALSE;
  }
propagate_exception:
  {
    if (exception != NULL)
      *exception = ex;
    return FALSE;
  }
}

gchar *
_gumjs_object_get_string (JSContextRef ctx,
                          JSObjectRef object,
                          const gchar * key)
{
  gchar * value;
  JSValueRef exception;

  if (!_gumjs_object_try_get_string (ctx, object, key, &value, &exception))
    _gumjs_panic (ctx, exception);

  return value;
}

gboolean
_gumjs_object_try_get_string (JSContextRef ctx,
                              JSObjectRef object,
                              const gchar * key,
                              gchar ** value,
                              JSValueRef * exception)
{
  JSValueRef v;

  if (!_gumjs_object_try_get (ctx, object, key, &v, exception))
    return FALSE;

  if (!JSValueIsString (ctx, v))
    goto invalid_type;

  return _gumjs_try_string_from_value (ctx, v, value, exception);

invalid_type:
  {
    _gumjs_throw (ctx, exception, "expected '%s' to be a string", key);
    return FALSE;
  }
}

void
_gumjs_object_set (JSContextRef ctx,
                   JSObjectRef object,
                   const gchar * key,
                   JSValueRef value)
{
  JSValueRef exception;

  if (!_gumjs_object_try_set (ctx, object, key, value, &exception))
    _gumjs_panic (ctx, exception);
}

gboolean
_gumjs_object_try_set (JSContextRef ctx,
                       JSObjectRef object,
                       const gchar * key,
                       JSValueRef value,
                       JSValueRef * exception)
{
  JSStringRef property;
  JSValueRef ex = NULL;

  property = JSStringCreateWithUTF8CString (key);
  JSObjectSetProperty (ctx, object, property, value,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, &ex);
  JSStringRelease (property);

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;
}

void
_gumjs_object_set_string (JSContextRef ctx,
                          JSObjectRef object,
                          const gchar * key,
                          const gchar * value)
{
  JSValueRef exception;

  if (!_gumjs_object_try_set_string (ctx, object, key, value, &exception))
    _gumjs_panic (ctx, exception);
}

gboolean
_gumjs_object_try_set_string (JSContextRef ctx,
                              JSObjectRef object,
                              const gchar * key,
                              const gchar * value,
                              JSValueRef * exception)
{
  return _gumjs_object_try_set (ctx, object, key,
      _gumjs_string_to_value (ctx, value), exception);
}

void
_gumjs_object_set_function (JSContextRef ctx,
                            JSObjectRef object,
                            const gchar * key,
                            JSObjectCallAsFunctionCallback callback)
{
  JSValueRef exception;

  if (!_gumjs_object_try_set_function (ctx, object, key, callback, &exception))
    _gumjs_panic (ctx, exception);
}

gboolean
_gumjs_object_try_set_function (JSContextRef ctx,
                                JSObjectRef object,
                                const gchar * key,
                                JSObjectCallAsFunctionCallback callback,
                                JSValueRef * exception)
{
  JSStringRef name;
  JSObjectRef func;
  JSValueRef ex = NULL;

  name = JSStringCreateWithUTF8CString (key);
  func = JSObjectMakeFunctionWithCallback (ctx, name, callback);
  JSObjectSetProperty (ctx, object, name, func,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, &ex);
  JSStringRelease (name);

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;
}

gboolean
_gumjs_callbacks_try_get (JSContextRef ctx,
                          JSValueRef callbacks,
                          const gchar * name,
                          JSObjectRef * callback,
                          JSValueRef * exception)
{
  if (!_gumjs_callbacks_try_get_opt (ctx, callbacks, name, callback, exception))
    return FALSE;

  if (*callback == NULL)
    goto callback_required;

  return TRUE;

callback_required:
  {
    _gumjs_throw (ctx, exception, "'%s' callback required", name);
    return FALSE;
  }
}

gboolean
_gumjs_callbacks_try_get_opt (JSContextRef ctx,
                              JSValueRef callbacks,
                              const gchar * name,
                              JSObjectRef * callback,
                              JSValueRef * exception)
{
  JSObjectRef obj;
  JSValueRef value;

  if (!JSValueIsObject (ctx, callbacks))
    goto invalid_argument;
  obj = (JSObjectRef) callbacks;

  if (!_gumjs_object_try_get (ctx, obj, name, &value, exception))
    return FALSE;

  return _gumjs_callback_try_get_opt (ctx, value, callback, exception);

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "expected object containing callbacks");
    return FALSE;
  }
}

gboolean
_gumjs_callback_try_get (JSContextRef ctx,
                         JSValueRef value,
                         JSObjectRef * callback,
                         JSValueRef * exception)
{
  if (!_gumjs_callback_try_get_opt (ctx, value, callback, exception))
    return FALSE;

  if (*callback == NULL)
    goto callback_required;

  return TRUE;

callback_required:
  {
    _gumjs_throw (ctx, exception, "callback required");
    return FALSE;
  }
}

gboolean
_gumjs_callback_try_get_opt (JSContextRef ctx,
                             JSValueRef value,
                             JSObjectRef * callback,
                             JSValueRef * exception)
{
  if (!JSValueIsUndefined (ctx, value) && !JSValueIsNull (ctx, value))
  {
    JSObjectRef obj;

    if (!JSValueIsObject (ctx, value))
      goto invalid_argument;

    obj = (JSObjectRef) value;
    if (!JSObjectIsFunction (ctx, obj))
      goto invalid_argument;

    *callback = obj;
  }
  else
  {
    *callback = NULL;
  }

  return TRUE;

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "expected function");
    return FALSE;
  }
}

JSValueRef
_gumjs_native_pointer_new (JSContextRef ctx,
                           gpointer address,
                           GumScriptCore * core)
{
  return JSObjectMake (ctx, core->native_pointer, address);
}

gboolean
_gumjs_native_pointer_try_get (JSContextRef ctx,
                               JSValueRef value,
                               GumScriptCore * core,
                               gpointer * target,
                               JSValueRef * exception)
{

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
_gumjs_array_buffer_new (JSContextRef ctx,
                         gsize size,
                         GumScriptCore * core)
{
  JSValueRef size_value;

  size_value = JSValueMakeNumber (ctx, size);

  return JSObjectCallAsConstructor (ctx, core->array_buffer, 1, &size_value,
      NULL);
}

gboolean
_gumjs_byte_array_try_get (JSContextRef ctx,
                           JSValueRef value,
                           GBytes ** bytes,
                           JSValueRef * exception)
{
  if (!_gumjs_byte_array_try_get_opt (ctx, value, bytes, exception))
    return FALSE;

  if (*bytes == NULL)
    goto byte_array_required;

  return TRUE;

byte_array_required:
  {
    _gumjs_throw (ctx, exception, "byte array required");
    return FALSE;
  }
}

gboolean
_gumjs_byte_array_try_get_opt (JSContextRef ctx,
                               JSValueRef value,
                               GBytes ** bytes,
                               JSValueRef * exception)
{
  gpointer buffer_data;
  gsize buffer_size;
  guint8 * data;

  if (_gumjs_array_buffer_try_get_data (ctx, value, &buffer_data, &buffer_size,
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

  if (exception != NULL)
    *exception = JSObjectMakeError (ctx, 1, &message_value, NULL);
}

void
_gumjs_throw_native (JSContextRef ctx,
                     JSValueRef * exception,
                     GumExceptionDetails * details,
                     GumScriptCore * core)
{
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
