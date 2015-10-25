/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptvalue.h"

#include "gumjscript-priv.h"

#define GUM_SCRIPT_MAX_ARRAY_LENGTH (1024 * 1024)

static void gum_native_resource_on_weak_notify (
    GumScriptNativeResource * resource);

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
  GSList * strings = NULL, * byte_arrays = NULL;

  va_start (ap, format);

  arg_index = 0;
  is_required = TRUE;
  for (t = format; *t != '\0'; t++)
  {
    JSValueRef value;

    if (*t == '|')
    {
      is_required = FALSE;
      continue;
    }

    if (arg_index < self->count)
    {
      value = self->values[arg_index];
    }
    else
    {
      if (is_required)
        goto missing_argument;
      else
        break;
    }

    switch (*t)
    {
      case 'i':
      {
        gint i;

        if (!_gumjs_int_try_get (ctx, value, &i, exception))
          goto error;

        *va_arg (ap, gint *) = i;

        break;
      }
      case 'u':
      {
        guint i;

        if (!_gumjs_uint_try_get (ctx, value, &i, exception))
          goto error;

        *va_arg (ap, guint *) = i;

        break;
      }
      case 'n':
      {
        gdouble number;

        if (!_gumjs_number_try_get (ctx, value, &number, exception))
          goto error;

        *va_arg (ap, gdouble *) = number;

        break;
      }
      case 'p':
      {
        gboolean is_fuzzy;
        gpointer ptr;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (_gumjs_native_pointer_try_get (ctx, value, core, &ptr, NULL))
            ;
          else if (JSValueIsString (ctx, value))
          {
            gchar * ptr_as_string, * endptr;
            gboolean valid;

            if (!_gumjs_string_try_get (ctx, value, &ptr_as_string, exception))
              goto error;

            if (g_str_has_prefix (ptr_as_string, "0x"))
            {
              ptr = GSIZE_TO_POINTER (
                  g_ascii_strtoull (ptr_as_string + 2, &endptr, 16));
              valid = endptr != ptr_as_string + 2;
              if (!valid)
              {
                _gumjs_throw (ctx, exception,
                    "argument is not a valid hexadecimal string");
              }
            }
            else
            {
              ptr = GSIZE_TO_POINTER (
                  g_ascii_strtoull (ptr_as_string, &endptr, 10));
              valid = endptr != ptr_as_string;
              if (!valid)
              {
                _gumjs_throw (ctx, exception,
                    "argument is not a valid decimal string");
              }
            }

            g_free (ptr_as_string);

            if (!valid)
              goto error;
          }
          else if (JSValueIsNumber (ctx, value))
          {
            guint i;

            if (!_gumjs_uint_try_get (ctx, value, &i, exception))
              goto error;

            ptr = GSIZE_TO_POINTER (i);
          }
          else
          {
            _gumjs_throw (ctx, exception, "invalid pointer value");
            goto error;
          }
        }
        else
        {
          if (!_gumjs_native_pointer_try_get (ctx, value, core, &ptr,
              exception))
            goto error;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;
        gchar * prot_str, * ch;
        gboolean valid;

        if (!_gumjs_string_try_get (ctx, value, &prot_str, NULL))
        {
          _gumjs_throw (ctx, exception,
              "expected string specifying memory protection");
          goto error;
        }

        prot = GUM_PAGE_NO_ACCESS;
        valid = TRUE;
        for (ch = prot_str; *ch != '\0' && valid; ch++)
        {
          switch (*ch)
          {
            case 'r':
              prot |= GUM_PAGE_READ;
              break;
            case 'w':
              prot |= GUM_PAGE_WRITE;
              break;
            case 'x':
              prot |= GUM_PAGE_EXECUTE;
              break;
            case '-':
              break;
            default:
              _gumjs_throw (ctx, exception,
                  "invalid character in memory protection specifier string");
              valid = FALSE;
              break;
          }
        }

        g_free (prot_str);

        if (valid)
          *va_arg (ap, GumPageProtection *) = prot;
        else
          goto error;

        break;
      }
      case 's':
      {
        gchar * str;

        if (!_gumjs_string_try_get (ctx, value, &str, exception))
          goto error;

        *va_arg (ap, gchar **) = str;

        strings = g_slist_prepend (strings, str);

        break;
      }
      case 'V':
      {
        *va_arg (ap, JSValueRef *) = value;

        break;
      }
      case 'A':
      {
        JSObjectRef array;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JSValueIsArray (ctx, value))
        {
          array = (JSObjectRef) value;
        }
        else if (is_nullable &&
            (JSValueIsUndefined (ctx, value) || JSValueIsNull (ctx, value)))
        {
          array = NULL;
        }
        else
        {
          _gumjs_throw (ctx, exception, "expected an array");
          goto error;
        }

        *va_arg (ap, JSObjectRef *) = array;

        break;
      }
      case 'F':
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

        *va_arg (ap, GBytes **) = bytes;

        byte_arrays = g_slist_prepend (byte_arrays, bytes);

        break;
      }
      case 'C':
      {
        GumCpuContext * cpu_context;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable)
        {
          if (!_gumjs_cpu_context_try_get_opt (ctx, value, core, &cpu_context,
              exception))
            goto error;
        }
        else
        {
          if (!_gumjs_cpu_context_try_get (ctx, value, core, &cpu_context,
              exception))
            goto error;
        }

        *va_arg (ap, GumCpuContext **) = cpu_context;

        break;
      }
      default:
        g_assert_not_reached ();
    }

    arg_index++;
  }

  va_end (ap);

  g_slist_free (strings);
  g_slist_free (byte_arrays);

  return TRUE;

missing_argument:
  {
    _gumjs_throw (ctx, exception, "missing argument");
    goto error;
  }
error:
  {
    va_end (ap);

    g_slist_foreach (strings, (GFunc) g_free, NULL);
    g_slist_free (strings);
    g_slist_foreach (byte_arrays, (GFunc) g_bytes_unref, NULL);
    g_slist_free (byte_arrays);

    return FALSE;
  }
}

gboolean
_gumjs_int_try_get (JSContextRef ctx,
                    JSValueRef value,
                    gint * i,
                    JSValueRef * exception)
{
  double number;

  if (!_gumjs_number_try_get (ctx, value, &number, exception))
    return FALSE;

  *i = (gint) number;

  return TRUE;
}

gboolean
_gumjs_uint_try_get (JSContextRef ctx,
                     JSValueRef value,
                     guint * i,
                     JSValueRef * exception)
{
  double number;

  if (!_gumjs_number_try_get (ctx, value, &number, exception))
    return FALSE;

  if (number < 0)
    goto invalid_uint;

  *i = (guint) number;

  return TRUE;

invalid_uint:
  {
    _gumjs_throw (ctx, exception, "expected a non-negative number");
    return FALSE;
  }
}

gboolean
_gumjs_uint_try_parse (JSContextRef ctx,
                       JSStringRef str,
                       guint * i,
                       JSValueRef * exception)
{
  gchar * str_utf8, * endptr;
  glong value;
  gboolean valid;

  str_utf8 = _gumjs_string_from_jsc (str);
  value = strtol (str_utf8, &endptr, 10);
  valid = *str_utf8 != '\0' && *endptr == '\0' && value >= 0;
  g_free (str_utf8);

  if (valid)
    *i = value;
  else
    _gumjs_throw (ctx, exception, "invalid uint");

  return valid;
}

gboolean
_gumjs_number_try_get (JSContextRef ctx,
                       JSValueRef value,
                       gdouble * number,
                       JSValueRef * exception)
{
  JSValueRef ex = NULL;

  if (!JSValueIsNumber (ctx, value))
    goto invalid_type;

  *number = JSValueToNumber (ctx, value, &ex);

  if (exception != NULL)
    *exception = ex;

  return ex == NULL;

invalid_type:
  {
    _gumjs_throw (ctx, exception, "expected a number");
    return FALSE;
  }
}

gchar *
_gumjs_string_get (JSContextRef ctx,
                   JSValueRef value)
{
  gchar * str;
  JSValueRef exception;

  if (!_gumjs_string_try_get (ctx, value, &str, &exception))
    _gumjs_panic (ctx, exception);

  return str;
}

gboolean
_gumjs_string_try_get (JSContextRef ctx,
                       JSValueRef value,
                       gchar ** str,
                       JSValueRef * exception)
{
  JSStringRef s;

  if (!JSValueIsString (ctx, value))
    goto invalid_type;

  s = JSValueToStringCopy (ctx, value, exception);
  if (s == NULL)
    return FALSE;
  *str = _gumjs_string_from_jsc (s);
  JSStringRelease (s);

  return TRUE;

invalid_type:
  {
    _gumjs_throw (ctx, exception, "expected a string");
    return FALSE;
  }
}

gchar *
_gumjs_string_from_jsc (JSStringRef str)
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
  JSStringRef s;

  s = JSValueToStringCopy (ctx, value, NULL);
  g_assert (s != NULL);
  str = _gumjs_string_from_jsc (s);
  JSStringRelease (s);

  return str;
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
  JSValueRef v;

  if (!_gumjs_object_try_get (ctx, object, key, &v, exception))
    return FALSE;

  return _gumjs_uint_try_get (ctx, v, value, exception);
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

  return _gumjs_string_try_get (ctx, v, value, exception);
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
_gumjs_object_set_int (JSContextRef ctx,
                       JSObjectRef object,
                       const gchar * key,
                       gint value)
{
  JSValueRef exception;

  if (!_gumjs_object_try_set_int (ctx, object, key, value, &exception))
    _gumjs_panic (ctx, exception);
}

gboolean
_gumjs_object_try_set_int (JSContextRef ctx,
                           JSObjectRef object,
                           const gchar * key,
                           gint value,
                           JSValueRef * exception)
{
  return _gumjs_object_try_set (ctx, object, key,
      JSValueMakeNumber (ctx, value), exception);
}

void
_gumjs_object_set_uint (JSContextRef ctx,
                        JSObjectRef object,
                        const gchar * key,
                        guint value)
{
  JSValueRef exception;

  if (!_gumjs_object_try_set_uint (ctx, object, key, value, &exception))
    _gumjs_panic (ctx, exception);
}

gboolean
_gumjs_object_try_set_uint (JSContextRef ctx,
                            JSObjectRef object,
                            const gchar * key,
                            guint value,
                            JSValueRef * exception)
{
  return _gumjs_object_try_set (ctx, object, key,
      JSValueMakeNumber (ctx, value), exception);
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

JSObjectRef
_gumjs_native_pointer_new (JSContextRef ctx,
                           gpointer address,
                           GumScriptCore * core)
{
  GumScriptNativePointer * ptr;

  ptr = g_slice_new (GumScriptNativePointer);
  ptr->instance_size = sizeof (GumScriptNativePointer);
  ptr->value = address;

  return JSObjectMake (ctx, core->native_pointer, ptr);
}

gpointer
_gumjs_native_pointer_value (JSValueRef value)
{
  GumScriptNativePointer * ptr;

  ptr = JSObjectGetPrivate ((JSObjectRef) value);

  return ptr->value;
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
    *target = _gumjs_native_pointer_value (value);
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
_gumjs_cpu_context_new (JSContextRef ctx,
                        GumCpuContext * handle,
                        GumScriptCpuContextAccess access,
                        GumScriptCore * core)
{
  GumScriptCpuContext * scc;

  scc = g_slice_new (GumScriptCpuContext);
  if (access == GUM_CPU_CONTEXT_READWRITE)
  {
    scc->handle = handle;
  }
  else
  {
    memcpy (&scc->storage, handle, sizeof (GumCpuContext));
    scc->handle = &scc->storage;
  }
  scc->access = access;

  return JSObjectMake (ctx, core->cpu_context, scc);
}

void
_gumjs_cpu_context_detach (JSValueRef value)
{
  GumScriptCpuContext * self;

  self = JSObjectGetPrivate ((JSObjectRef) value);

  if (self->access == GUM_CPU_CONTEXT_READWRITE)
  {
    memcpy (&self->storage, self->handle, sizeof (GumCpuContext));
    self->handle = &self->storage;
    self->access = GUM_CPU_CONTEXT_READONLY;
  }
}

gboolean
_gumjs_cpu_context_try_get (JSContextRef ctx,
                            JSValueRef value,
                            GumScriptCore * core,
                            GumCpuContext ** cpu_context,
                            JSValueRef * exception)
{
  if (!_gumjs_cpu_context_try_get_opt (ctx, value, core, cpu_context,
      exception))
    return FALSE;

  if (*cpu_context == NULL)
    goto cpu_context_required;

  return TRUE;

cpu_context_required:
  {
    _gumjs_throw (ctx, exception, "CpuContext required");
    return FALSE;
  }
}

gboolean
_gumjs_cpu_context_try_get_opt (JSContextRef ctx,
                                JSValueRef value,
                                GumScriptCore * core,
                                GumCpuContext ** cpu_context,
                                JSValueRef * exception)
{
  if (JSValueIsObjectOfClass (ctx, value, core->cpu_context))
  {
    GumScriptCpuContext * instance;

    instance = JSObjectGetPrivate ((JSObjectRef) value);

    *cpu_context = instance->handle;
    return TRUE;
  }
  else if (JSValueIsUndefined (ctx, value) || JSValueIsNull (ctx, value))
  {
    *cpu_context = NULL;
    return TRUE;
  }

  goto invalid_value;

invalid_value:
  {
    _gumjs_throw (ctx, exception, "invalid CpuContext value");
    return FALSE;
  }
}

GumScriptNativeResource *
_gumjs_native_resource_new (JSContextRef ctx,
                            gpointer data,
                            GDestroyNotify notify,
                            GumScriptCore * core,
                            JSObjectRef * handle)
{
  JSObjectRef h;
  GumScriptNativeResource * resource;

  h = _gumjs_native_pointer_new (ctx, data, core);

  resource = g_slice_new (GumScriptNativeResource);
  resource->weak_ref = _gumjs_weak_ref_new (ctx, h,
      (GumScriptWeakNotify) gum_native_resource_on_weak_notify, resource, NULL);
  resource->data = data;
  resource->notify = notify;
  resource->core = core;

  g_hash_table_insert (core->native_resources, resource, resource);

  *handle = h;

  return resource;
}

void
_gumjs_native_resource_free (GumScriptNativeResource * resource)
{
  _gumjs_weak_ref_free (resource->weak_ref);

  if (resource->notify != NULL)
    resource->notify (resource->data);

  g_slice_free (GumScriptNativeResource, resource);
}

static void
gum_native_resource_on_weak_notify (GumScriptNativeResource * self)
{
  g_hash_table_remove (self->core->native_resources, self);
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
