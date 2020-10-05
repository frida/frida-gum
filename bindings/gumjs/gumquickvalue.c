/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickvalue.h"

#include <stdarg.h>

gboolean
_gum_quick_args_parse (const GumQuickArgs * args,
                       const gchar * format,
                       ...)
{
  JSContext * ctx = args->ctx;
  GumQuickCore * core = args->core;
  va_list ap;
  int arg_index, arg_count;
  const gchar * t;
  gboolean is_required;
  GSList * byte_arrays = NULL;
  const gchar * error_message = NULL;

  va_start (ap, format);

  arg_index = 0;
  arg_count = args->argc;
  is_required = TRUE;
  for (t = format; *t != '\0'; t++)
  {
    JSValue arg;

    if (*t == '|')
    {
      is_required = FALSE;
      continue;
    }

    arg = (arg_index < arg_count) ? args->argv[arg_index] : JS_UNDEFINED;

    if (JS_IsUndefined (arg))
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

        if (!_gum_quick_int_get (ctx, arg, &i))
          goto error;

        *va_arg (ap, gint *) = i;

        break;
      }
      case 'u':
      {
        guint u;

        if (!_gum_quick_uint_get (ctx, arg, &u))
          goto error;

        *va_arg (ap, guint *) = (guint) u;

        break;
      }
      case 'q':
      {
        gint64 i;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_int64_parse (ctx, arg, core, &i))
            goto error;
        }
        else
        {
          if (!_gum_quick_int64_get (ctx, arg, core, &i))
            goto error;
        }

        *va_arg (ap, gint64 *) = i;

        break;
      }
      case 'Q':
      {
        guint64 u;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_uint64_parse (ctx, arg, core, &u))
            goto error;
        }
        else
        {
          if (!_gum_quick_uint64_get (ctx, arg, core, &u))
            goto error;
        }

        *va_arg (ap, guint64 *) = u;

        break;
      }
#if 0
      case 'z':
      {
        gssize value;

        if (!_gum_quick_ssize_get (ctx, arg, core, &value))
          goto expected_int;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_quick_size_get (ctx, arg, core, &value))
          goto expected_int;

        *va_arg (ap, gsize *) = value;

        break;
      }
#endif
      case 'n':
      {
        gdouble d;

        if (!_gum_quick_float64_get (ctx, arg, &d))
          goto error;

        *va_arg (ap, gdouble *) = d;

        break;
      }
#if 0
      case 't':
      {
        gboolean b;

        if (!_gum_quick_bool_get (ctx, arg, &b))
          goto error;

        *va_arg (ap, gboolean *) = b;

        break;
      }
#endif
      case 'p':
      {
        gpointer ptr;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_native_pointer_parse (ctx, arg, core, &ptr))
            goto error;
        }
        else
        {
          if (!_gum_quick_native_pointer_get (ctx, arg, core, &ptr))
            goto error;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 's':
      {
        const gchar * str;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && JS_IsNull (arg))
          str = NULL;
        else if ((str = quick_get_string (ctx, arg)) == NULL)
          goto expected_string;

        *va_arg (ap, const gchar **) = str;

        break;
      }
      case 'R':
      {
        GArray * ranges;

        ranges = _gum_quick_get_memory_ranges (ctx, arg, core);
        if (ranges == NULL)
          goto expected_array_ranges;

        *va_arg (ap, GArray **) = ranges;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_quick_parse_protection (ctx, arg, &prot))
          goto expected_protection;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        GumDukHeapPtr value;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && quick_is_null (ctx, arg))
        {
          value = NULL;
        }
        else
        {
          value = quick_get_heapptr (ctx, arg);
          if (value == NULL)
            goto expected_heap_pointer;
        }

        *va_arg (ap, GumDukHeapPtr *) = value;

        break;
      }
      case 'O':
      {
        GumDukHeapPtr object;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && quick_is_null (ctx, arg))
          object = NULL;
        else if (quick_is_object (ctx, arg))
          object = quick_require_heapptr (ctx, arg);
        else
          goto expected_object;

        *va_arg (ap, GumDukHeapPtr *) = object;

        break;
      }
      case 'A':
      {
        GumDukHeapPtr array;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (quick_is_array (ctx, arg))
          array = quick_require_heapptr (ctx, arg);
        else if (is_nullable && quick_is_null (ctx, arg))
          array = NULL;
        else
          goto expected_array;

        *va_arg (ap, GumDukHeapPtr *) = array;

        break;
      }
      case 'F':
      {
        GumDukHeapPtr func_js;
        gpointer func_c;
        gboolean accepts_pointer, is_expecting_object;

        accepts_pointer = t[1] == '*';
        if (accepts_pointer)
          t++;

        is_expecting_object = t[1] == '{';
        if (is_expecting_object)
          t += 2;

        if (is_expecting_object)
        {
          const gchar * next, * end, * t_end;

          if (!quick_is_object (ctx, arg))
            goto expected_callback_object;

          do
          {
            gchar name[64];
            gsize length;
            gboolean is_optional;

            next = strchr (t, ',');
            end = strchr (t, '}');
            t_end = (next != NULL && next < end) ? next : end;
            length = t_end - t;
            strncpy (name, t, length);

            is_optional = name[length - 1] == '?';
            if (is_optional)
              name[length - 1] = '\0';
            else
              name[length] = '\0';

            quick_get_prop_string (ctx, arg, name);
            if (quick_is_function (ctx, -1))
            {
              func_js = quick_require_heapptr (ctx, -1);
              func_c = NULL;
            }
            else if (is_optional && quick_is_undefined (ctx, -1))
            {
              func_js = NULL;
              func_c = NULL;
            }
            else if (accepts_pointer)
            {
              func_js = NULL;
              func_c = _gum_quick_require_native_pointer (ctx, -1, core)->value;
            }
            else
            {
              quick_pop (ctx);
              goto expected_callback_value;
            }
            quick_pop (ctx);

            *va_arg (ap, GumDukHeapPtr *) = func_js;
            if (accepts_pointer)
              *va_arg (ap, gpointer *) = func_c;

            t = t_end + 1;
          }
          while (t_end != end);

          t--;
        }
        else
        {
          gboolean is_nullable;

          is_nullable = t[1] == '?';
          if (is_nullable)
            t++;

          if (quick_is_function (ctx, arg))
          {
            func_js = quick_require_heapptr (ctx, arg);
            func_c = NULL;
          }
          else if (is_nullable && quick_is_null (ctx, arg))
          {
            func_js = NULL;
            func_c = NULL;
          }
          else if (accepts_pointer)
          {
            func_js = NULL;
            func_c = _gum_quick_require_native_pointer (ctx, arg,
                core)->value;
          }
          else
          {
            goto expected_function;
          }

          *va_arg (ap, GumDukHeapPtr *) = func_js;
          if (accepts_pointer)
            *va_arg (ap, gpointer *) = func_c;
        }

        break;
      }
      case 'B':
      {
        GBytes * bytes;
        gboolean is_fuzzy, is_nullable;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;
        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && quick_is_null (ctx, arg))
        {
          bytes = NULL;
        }
        else
        {
          gboolean success;

          if (is_fuzzy)
            success = _gum_quick_parse_bytes (ctx, arg, &bytes);
          else
            success = _gum_quick_get_bytes (ctx, arg, &bytes);

          if (!success)
            goto expected_bytes;
        }

        *va_arg (ap, GBytes **) = bytes;

        if (bytes != NULL)
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

        if (is_nullable && quick_is_null (ctx, arg))
          cpu_context = NULL;
        else if ((cpu_context = _gum_quick_get_cpu_context (ctx, arg,
            core)) == NULL)
          goto expected_cpu_context;

        *va_arg (ap, GumCpuContext **) = cpu_context;

        break;
      }
      default:
        g_assert_not_reached ();
    }

    arg_index++;
  }

  va_end (ap);

  g_slist_free (byte_arrays);

  return TRUE;

missing_argument:
  {
    error_message = "missing argument";
    goto error;
  }
expected_number:
  {
    error_message = "expected a number";
    goto error;
  }
expected_boolean:
  {
    error_message = "expected a boolean";
    goto error;
  }
expected_pointer:
  {
    error_message = "expected a pointer";
    goto error;
  }
expected_string:
  {
    error_message = "expected a string";
    goto error;
  }
expected_protection:
  {
    error_message = "expected a string specifying memory protection";
    goto error;
  }
expected_heap_pointer:
  {
    error_message = "expected a heap-allocated object";
    goto error;
  }
expected_object:
  {
    error_message = "expected an object";
    goto error;
  }
expected_array:
  {
    error_message = "expected an array";
    goto error;
  }
expected_callback_object:
  {
    error_message = "expected an object containing callbacks";
    goto error;
  }
expected_callback_value:
  {
    error_message = "expected a callback value";
    goto error;
  }
expected_function:
  {
    error_message = "expected a function";
    goto error;
  }
expected_bytes:
  {
    error_message = "expected a buffer-like object";
    goto error;
  }
expected_cpu_context:
  {
    error_message = "expected a CpuContext object";
    goto error;
  }
expected_array_ranges:
  {
    error_message = "expected a range object or array of ranges objects";
    goto error;
  }
error:
  {
    va_end (ap);

    g_slist_foreach (byte_arrays, (GFunc) g_bytes_unref, NULL);
    g_slist_free (byte_arrays);

    if (error_message != NULL)
      _gum_quick_throw_literal (ctx, error_message);

    return FALSE;
  }
}

void
_gum_quick_store_module_data (JSContext * ctx,
                              const gchar * module_id,
                              gpointer data)
{
}

gpointer
_gum_quick_load_module_data (JSContext * ctx,
                             const gchar * module_id)
{
  return NULL;
}

gboolean
_gum_quick_int_get (JSContext * ctx,
                    JSValueConst val,
                    gint * i)
{
  int32_t v;

  if (!JS_IsNumber (val))
    goto expected_int;

  if (JS_ToInt32 (ctx, &v, val) != 0)
    return FALSE;

  *i = v;
  return TRUE;

expected_int:
  {
    _gum_quick_throw_literal (ctx, "expected an integer");
    return FALSE;
  }
}

gboolean
_gum_quick_uint_get (JSContext * ctx,
                     JSValueConst val,
                     guint * u)
{
  uint32_t v;

  if (!JS_IsNumber (val))
    goto expected_uint;

  if (JS_ToUint32 (ctx, &v, val) != 0)
    return FALSE;

  *u = v;
  return TRUE;

expected_uint:
  {
    _gum_quick_throw_literal (ctx, "expected an unsigned integer");
    return FALSE;
  }
}

JSValue
_gum_quick_int64_new (JSContext * ctx,
                      gint64 i,
                      GumQuickCore * core)
{
  JSValue obj;
  GumQuickInt64 * self;

  obj = JS_NewObjectClass (ctx, core->int64_class);

  self = g_slice_new (GumQuickInt64);
  self->value = i;

  JS_SetOpaque (obj, self);

  return obj;
}

gboolean
_gum_quick_int64_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      gint64 * i)
{
  if (JS_IsNumber (val))
  {
    int32_t v;

    if (JS_ToInt32 (ctx, &v, val) != 0)
      return FALSE;

    *i = v;
  }
  else
  {
    GumQuickInt64 * self;

    self = JS_GetOpaque2 (ctx, val, core->int64_class);
    if (self == NULL)
      return FALSE;

    *i = self->value;
  }

  return TRUE;
}

gboolean
_gum_quick_int64_parse (JSContext * ctx,
                        JSValueConst val,
                        GumQuickCore * core,
                        gint64 * i)
{
  if (JS_IsString (val))
  {
    const gchar * value_as_string, * end;
    gboolean valid;

    value_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *i = g_ascii_strtoll (value_as_string + 2, (gchar **) &end, 16);
      valid = end != value_as_string + 2;
    }
    else
    {
      *i = g_ascii_strtoll (value_as_string, (gchar **) &end, 10);
      valid = end != value_as_string;
    }

    JS_FreeCString (ctx, value_as_string);

    if (!valid)
      _gum_quick_throw_literal (ctx, "expected an integer");

    return valid;
  }

  return _gum_quick_int64_get (ctx, val, core, i);
}

JSValue
_gum_quick_uint64_new (JSContext * ctx,
                       guint64 u,
                       GumQuickCore * core)
{
  JSValue obj;
  GumQuickUInt64 * self;

  obj = JS_NewObjectClass (ctx, core->uint64_class);

  self = g_slice_new (GumQuickUInt64);
  self->value = u;

  JS_SetOpaque (obj, self);

  return obj;
}

gboolean
_gum_quick_uint64_get (JSContext * ctx,
                       JSValueConst val,
                       GumQuickCore * core,
                       guint64 * u)
{
  if (JS_IsNumber (val))
  {
    uint32_t v;

    if (JS_ToUint32 (ctx, &v, val) != 0)
      return FALSE;

    *u = v;
  }
  else
  {
    GumQuickUInt64 * self;

    self = JS_GetOpaque2 (ctx, val, core->uint64_class);
    if (self == NULL)
      return FALSE;

    *u = self->value;
  }

  return TRUE;
}

gboolean
_gum_quick_uint64_parse (JSContext * ctx,
                         JSValueConst val,
                         GumQuickCore * core,
                         guint64 * u)
{
  if (JS_IsString (val))
  {
    const gchar * value_as_string, * end;
    gboolean valid;

    value_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *u = g_ascii_strtoull (value_as_string + 2, (gchar **) &end, 16);
      valid = end != value_as_string + 2;
    }
    else
    {
      *u = g_ascii_strtoull (value_as_string, (gchar **) &end, 10);
      valid = end != value_as_string;
    }

    JS_FreeCString (ctx, value_as_string);

    if (!valid)
      _gum_quick_throw_literal (ctx, "expected an unsigned integer");

    return valid;
  }

  return _gum_quick_uint64_get (ctx, val, core, u);
}

gboolean
_gum_quick_float64_get (JSContext * ctx,
                        JSValueConst val,
                        gdouble * d)
{
  double v;

  if (!JS_IsNumber (val))
    goto expected_number;

  if (JS_ToFloat64 (ctx, &v, val) != 0)
    return FALSE;

  *d = v;
  return TRUE;

expected_number:
  {
    _gum_quick_throw_literal (ctx, "expected a number");
    return FALSE;
  }
}

JSValue
_gum_quick_native_pointer_new (JSContext * ctx,
                               gpointer ptr,
                               GumQuickCore * core)
{
  JSValue obj;
  GumQuickNativePointer * self;

  obj = JS_NewObjectClass (ctx, core->native_pointer_class);

  self = g_slice_new (GumQuickNativePointer);
  self->value = ptr;

  JS_SetOpaque (obj, self);

  return obj;
}

gboolean
_gum_quick_native_pointer_get (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               gpointer * ptr)
{
  return FALSE; /* TODO */
}

gboolean
_gum_quick_native_pointer_parse (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 gpointer * ptr)
{
  return FALSE; /* TODO */
}

gboolean
_gum_quick_array_get_length (JSContext * ctx,
                             JSValueConst array,
                             guint * length)
{
  JSValue val;
  int res;
  uint32_t v;

  val = JS_GetPropertyStr (ctx, array, "length");
  if (JS_IsException (val))
    return FALSE;

  res = JS_ToUint32 (ctx, &v, val);

  JS_FreeValue (ctx, val);

  if (res != 0)
    return FALSE;

  *length = v;
  return TRUE;
}

JSValue
_gum_quick_throw (JSContext * ctx,
                  const gchar * format,
                  ...)
{
  JSValue result;
  va_list args;
  gchar * message;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  result = _gum_quick_throw_literal (ctx, message);
  g_free (message);
  va_end (args);

  return result;
}

JSValue
_gum_quick_throw_literal (JSContext * ctx,
                          const gchar * message)
{
  JSValue error;

  error = JS_NewError (ctx);
  JS_SetPropertyStr (ctx, error, "message", JS_NewString (ctx, message));

  return JS_Throw (ctx, error);
}

JSValue
_gum_quick_throw_native (JSContext * ctx,
                         GumExceptionDetails * details,
                         GumQuickCore * core)
{
  return _gum_quick_throw_literal (ctx, "a native exception occurred");
}
