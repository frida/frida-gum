/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickvalue.h"

#include <stdarg.h>

#define GUM_MAX_JS_BYTE_ARRAY_LENGTH (100 * 1024 * 1024)

typedef struct _GumQuickJSValue GumQuickJSValue;

struct _GumQuickJSValue
{
  JSValue val;
  GumQuickCore * core;
};

static GumQuickJSValue * gum_quick_js_value_new (JSContext * ctx, JSValue val,
    GumQuickCore * core);
static void gum_quick_js_value_free (GumQuickJSValue * v);

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
      case 'z':
      {
        gssize value;

        if (!_gum_quick_ssize_get (ctx, arg, core, &value))
          goto error;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_quick_size_get (ctx, arg, core, &value))
          goto error;

        *va_arg (ap, gsize *) = value;

        break;
      }
      case 'n':
      {
        gdouble d;

        if (!_gum_quick_float64_get (ctx, arg, &d))
          goto error;

        *va_arg (ap, gdouble *) = d;

        break;
      }
      case 't':
      {
        gboolean b;

        if (!_gum_quick_boolean_get (ctx, arg, &b))
          goto error;

        *va_arg (ap, gboolean *) = b;

        break;
      }
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
        else if (!_gum_quick_string_get (ctx, arg, &str))
          goto error;

        *va_arg (ap, const char **) = str;

        break;
      }
      case 'R':
      {
        GArray * ranges;

        if (!_gum_quick_memory_ranges_get (ctx, arg, core, &ranges))
          goto error;

        *va_arg (ap, GArray **) = ranges;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_quick_page_protection_get (ctx, arg, &prot))
          goto error;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_object_or_string;
        }
        else if (!JS_IsObject (arg) && !JS_IsString (arg))
        {
          goto expected_object_or_string;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'O':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_object;
        }
        else if (!JS_IsObject (arg))
        {
          goto expected_object;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'A':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_array;
        }
        else if (!JS_IsArray (ctx, arg))
        {
          goto expected_array;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'F':
      {
        JSValue func_js;
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

          if (!JS_IsObject (arg))
            goto expected_callback_object;

          do
          {
            gchar name[64];
            gsize length;
            gboolean is_optional;
            JSValue val;

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

            val = JS_GetPropertyStr (ctx, arg, name);
            if (JS_IsFunction (ctx, val))
            {
              func_js = val;
              func_c = NULL;
            }
            else if (is_optional && JS_IsUndefined (val))
            {
              func_js = JS_NULL;
              func_c = NULL;
            }
            else if (accepts_pointer)
            {
              gboolean valid;

              func_js = JS_NULL;
              valid = _gum_quick_native_pointer_get (ctx, val, core, &func_c);

              JS_FreeValue (ctx, val);

              if (!valid)
                goto expected_callback_value;
            }
            else
            {
              JS_FreeValue (ctx, val);

              goto expected_callback_value;
            }

            *va_arg (ap, JSValue *) = func_js;
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

          if (JS_IsFunction (ctx, arg))
          {
            func_js = arg;
            func_c = NULL;
          }
          else if (is_nullable && JS_IsNull (arg))
          {
            func_js = arg;
            func_c = NULL;
          }
          else if (accepts_pointer)
          {
            func_js = JS_NULL;
            if (!_gum_quick_native_pointer_get (ctx, arg, core, &func_c))
              goto expected_function;
          }
          else
          {
            goto expected_function;
          }

          *va_arg (ap, JSValue *) = func_js;
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

        if (is_nullable && JS_IsNull (arg))
        {
          bytes = NULL;
        }
        else
        {
          gboolean success;

          if (is_fuzzy)
            success = _gum_quick_bytes_parse (ctx, arg, core, &bytes);
          else
            success = _gum_quick_bytes_get (ctx, arg, core, &bytes);

          if (!success)
            goto error;
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

        if (is_nullable && JS_IsNull (arg))
          cpu_context = NULL;
        else if (!_gum_quick_cpu_context_get (ctx, arg, core, &cpu_context))
          goto error;

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
expected_object_or_string:
  {
    error_message = "expected an object or string";
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
_gum_quick_string_get (JSContext * ctx,
                       JSValueConst val,
                       const char ** str)
{
  if (!JS_IsString (val))
    goto expected_string;

  *str = JS_ToCString (ctx, val);
  return *str != NULL;

expected_string:
  {
    _gum_quick_throw_literal (ctx, "expected a string");
    return FALSE;
  }
}

gboolean
_gum_quick_bytes_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      GBytes ** bytes)
{
  uint8_t * data;
  size_t size;
  JSValue element = JS_NULL;
  guint8 * tmp_array = NULL;

  data = JS_GetArrayBuffer (ctx, &size, val);
  if (data != NULL)
  {
    *bytes = g_bytes_new_with_free_func (data, size,
        (GDestroyNotify) gum_quick_js_value_free,
        gum_quick_js_value_new (ctx, val, core));
  }
  else if (JS_IsArray (ctx, val))
  {
    guint n, i;

    JS_FreeValue (ctx, JS_GetException (ctx));

    if (!_gum_quick_array_get_length (ctx, val, &n))
      return FALSE;

    if (n >= GUM_MAX_JS_BYTE_ARRAY_LENGTH)
      goto array_too_large;

    tmp_array = g_malloc (n);

    for (i = 0; i != n; i++)
    {
      uint32_t u;

      element = JS_GetPropertyUint32 (ctx, val, i);
      if (JS_IsException (element))
        goto propagate_exception;

      if (JS_ToUint32 (ctx, &u, element) != 0)
        goto propagate_exception;

      tmp_array[i] = u;

      JS_FreeValue (ctx, element);
      element = JS_NULL;
    }

    *bytes = g_bytes_new_take (tmp_array, n);
  }
  else
  {
    goto expected_bytes;
  }

  return TRUE;

expected_bytes:
  {
    _gum_quick_throw_literal (ctx, "expected a buffer-like object");
    goto propagate_exception;
  }
array_too_large:
  {
    _gum_quick_throw_literal (ctx, "array too large, use ArrayBuffer instead");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, element);
    g_free (tmp_array);

    return FALSE;
  }
}

gboolean
_gum_quick_bytes_parse (JSContext * ctx,
                        JSValueConst val,
                        GumQuickCore * core,
                        GBytes ** bytes)
{
  if (JS_IsString (val))
  {
    const char * str;

    str = JS_ToCString (ctx, val);

    *bytes = g_bytes_new (str, strlen (str));

    JS_FreeCString (ctx, str);

    return TRUE;
  }

  return _gum_quick_bytes_get (ctx, val, core, bytes);
}

gboolean
_gum_quick_boolean_get (JSContext * ctx,
                        JSValueConst val,
                        gboolean * b)
{
  if (!JS_IsBool (val))
    goto expected_boolean;

  *b = JS_VALUE_GET_BOOL (val);
  return TRUE;

expected_boolean:
  {
    _gum_quick_throw_literal (ctx, "expected a boolean");
    return FALSE;
  }
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
_gum_quick_size_get (JSContext * ctx,
                     JSValueConst val,
                     GumQuickCore * core,
                     gsize * size)
{
  _gum_quick_throw (ctx, "%s: TODO", G_STRFUNC);
  return FALSE; /* TODO */
}

gboolean
_gum_quick_ssize_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      gssize * size)
{
  _gum_quick_throw (ctx, "%s: TODO", G_STRFUNC);
  return FALSE; /* TODO */
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
  GumQuickNativePointer * p;

  p = JS_GetOpaque (val, core->native_pointer_class);
  if (p == NULL)
    goto expected_pointer;

  *ptr = p->value;
  return TRUE;

expected_pointer:
  {
    _gum_quick_throw_literal (ctx, "expected a pointer");
    return FALSE;
  }
}

gboolean
_gum_quick_native_pointer_parse (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 gpointer * ptr)
{
  GumQuickNativePointer * p;
  GumQuickUInt64 * u64;
  GumQuickInt64 * i64;

  if ((p = JS_GetOpaque (val, core->native_pointer_class)) != NULL)
  {
    *ptr = p->value;
  }
  else if (JS_IsString (val))
  {
    const gchar * ptr_as_string, * end;
    gboolean valid;

    ptr_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      *ptr = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string + 2, (gchar **) &end, 16));
      valid = end != ptr_as_string + 2;
    }
    else
    {
      *ptr = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string, (gchar **) &end, 10));
      valid = end != ptr_as_string;
    }

    JS_FreeCString (ctx, ptr_as_string);

    if (!valid)
      goto expected_pointer;
  }
  else if (JS_IsNumber (val))
  {
    union
    {
      gpointer p;
      int64_t i;
    } v;

    JS_ToInt64 (ctx, &v.i, val);

    *ptr = v.p;
  }
  else if ((u64 = JS_GetOpaque (val, core->uint64_class)) != NULL)
  {
    *ptr = GSIZE_TO_POINTER (u64->value);
  }
  else if ((i64 = JS_GetOpaque (val, core->int64_class)) != NULL)
  {
    *ptr = GSIZE_TO_POINTER (i64->value);
  }
  else
  {
    goto expected_pointer;
  }

  return TRUE;

expected_pointer:
  {
    _gum_quick_throw_literal (ctx, "expected a pointer");
    return FALSE;
  }
}

gboolean
_gum_quick_cpu_context_get (JSContext * ctx,
                            JSValueConst val,
                            GumQuickCore * core,
                            GumCpuContext ** cpu_context)
{
  _gum_quick_throw (ctx, "%s: TODO", G_STRFUNC);
  return FALSE; /* TODO */
}

gboolean
_gum_quick_memory_ranges_get (JSContext * ctx,
                              JSValueConst val,
                              GumQuickCore * core,
                              GArray ** ranges)
{
  _gum_quick_throw (ctx, "%s: TODO", G_STRFUNC);
  return FALSE; /* TODO */
}

gboolean
_gum_quick_page_protection_get (JSContext * ctx,
                                JSValueConst val,
                                GumPageProtection * prot)
{
  _gum_quick_throw (ctx, "%s: TODO", G_STRFUNC);
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

static GumQuickJSValue *
gum_quick_js_value_new (JSContext * ctx,
                        JSValue val,
                        GumQuickCore * core)
{
  GumQuickJSValue * v;

  v = g_slice_new (GumQuickJSValue);
  v->val = JS_DupValue (ctx, val);
  v->core = core;

  _gum_quick_core_pin (core);

  return v;
}

static void
gum_quick_js_value_free (GumQuickJSValue * v)
{
  GumQuickCore * core = v->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (core->ctx, v->val);
  g_slice_free (GumQuickJSValue, v);

  _gum_quick_core_unpin (core);

  _gum_quick_scope_leave (&scope);
}
