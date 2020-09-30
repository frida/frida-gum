/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickvalue.h"

void
_gum_quick_args_parse (const GumQuickArgs * args,
                       const gchar * format,
                       ...)
{
#if 0
  quick_context * ctx = args->ctx;
  GumQuickCore * core = args->core;
  va_list ap;
  quick_idx_t arg_index;
  const gchar * t;
  gboolean is_required;
  GSList * byte_arrays = NULL;
  const gchar * error_message = NULL;

  va_start (ap, format);

  arg_index = 0;
  is_required = TRUE;
  for (t = format; *t != '\0'; t++)
  {
    if (*t == '|')
    {
      is_required = FALSE;
      continue;
    }

    if (arg_index >= quick_get_top (ctx) || quick_is_undefined (ctx, arg_index))
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
        if (!quick_is_number (ctx, arg_index))
          goto expected_int;

        *va_arg (ap, gint *) = quick_require_int (ctx, arg_index);

        break;
      }
      case 'u':
      {
        guint u;

        if (!_gum_quick_get_uint (ctx, arg_index, &u))
          goto expected_uint;

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
          if (!_gum_quick_parse_int64 (ctx, arg_index, core, &i))
            goto expected_int;
        }
        else
        {
          if (!_gum_quick_get_int64 (ctx, arg_index, core, &i))
            goto expected_int;
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
          if (!_gum_quick_parse_uint64 (ctx, arg_index, core, &u))
            goto expected_uint;
        }
        else
        {
          if (!_gum_quick_get_uint64 (ctx, arg_index, core, &u))
            goto expected_uint;
        }

        *va_arg (ap, guint64 *) = u;

        break;
      }
      case 'z':
      {
        gssize value;

        if (!_gum_quick_get_ssize (ctx, arg_index, core, &value))
          goto expected_int;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_quick_get_size (ctx, arg_index, core, &value))
          goto expected_int;

        *va_arg (ap, gsize *) = value;

        break;
      }
      case 'n':
      {
        if (!quick_is_number (ctx, arg_index))
          goto expected_number;

        *va_arg (ap, gdouble *) = quick_require_number (ctx, arg_index);

        break;
      }
      case 't':
      {
        if (!quick_is_boolean (ctx, arg_index))
          goto expected_boolean;

        *va_arg (ap, gboolean *) = quick_require_boolean (ctx, arg_index);

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
          if (!_gum_quick_parse_pointer (ctx, arg_index, core, &ptr))
            goto expected_pointer;
        }
        else
        {
          if (!_gum_quick_get_pointer (ctx, arg_index, core, &ptr))
            goto expected_pointer;
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

        if (is_nullable && quick_is_null (ctx, arg_index))
          str = NULL;
        else if ((str = quick_get_string (ctx, arg_index)) == NULL)
          goto expected_string;

        *va_arg (ap, const gchar **) = str;

        break;
      }
      case 'R':
      {
        GArray * ranges;

        ranges = _gum_quick_get_memory_ranges (ctx, arg_index, core);
        if (ranges == NULL)
          goto expected_array_ranges;

        *va_arg (ap, GArray **) = ranges;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_quick_parse_protection (ctx, arg_index, &prot))
          goto expected_protection;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        GumQuickHeapPtr value;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && quick_is_null (ctx, arg_index))
        {
          value = NULL;
        }
        else
        {
          value = quick_get_heapptr (ctx, arg_index);
          if (value == NULL)
            goto expected_heap_pointer;
        }

        *va_arg (ap, GumQuickHeapPtr *) = value;

        break;
      }
      case 'O':
      {
        GumQuickHeapPtr object;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && quick_is_null (ctx, arg_index))
          object = NULL;
        else if (quick_is_object (ctx, arg_index))
          object = quick_require_heapptr (ctx, arg_index);
        else
          goto expected_object;

        *va_arg (ap, GumQuickHeapPtr *) = object;

        break;
      }
      case 'A':
      {
        GumQuickHeapPtr array;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (quick_is_array (ctx, arg_index))
          array = quick_require_heapptr (ctx, arg_index);
        else if (is_nullable && quick_is_null (ctx, arg_index))
          array = NULL;
        else
          goto expected_array;

        *va_arg (ap, GumQuickHeapPtr *) = array;

        break;
      }
      case 'F':
      {
        GumQuickHeapPtr func_js;
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

          if (!quick_is_object (ctx, arg_index))
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

            quick_get_prop_string (ctx, arg_index, name);
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

            *va_arg (ap, GumQuickHeapPtr *) = func_js;
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

          if (quick_is_function (ctx, arg_index))
          {
            func_js = quick_require_heapptr (ctx, arg_index);
            func_c = NULL;
          }
          else if (is_nullable && quick_is_null (ctx, arg_index))
          {
            func_js = NULL;
            func_c = NULL;
          }
          else if (accepts_pointer)
          {
            func_js = NULL;
            func_c = _gum_quick_require_native_pointer (ctx, arg_index,
                core)->value;
          }
          else
          {
            goto expected_function;
          }

          *va_arg (ap, GumQuickHeapPtr *) = func_js;
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

        if (is_nullable && quick_is_null (ctx, arg_index))
        {
          bytes = NULL;
        }
        else
        {
          gboolean success;

          if (is_fuzzy)
            success = _gum_quick_parse_bytes (ctx, arg_index, &bytes);
          else
            success = _gum_quick_get_bytes (ctx, arg_index, &bytes);

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

        if (is_nullable && quick_is_null (ctx, arg_index))
          cpu_context = NULL;
        else if ((cpu_context = _gum_quick_get_cpu_context (ctx, arg_index,
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

  return;

missing_argument:
  {
    error_message = "missing argument";
    goto error;
  }
expected_int:
  {
    error_message = "expected an integer";
    goto error;
  }
expected_uint:
  {
    error_message = "expected an unsigned integer";
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

    g_assert (error_message != NULL);
    _gum_quick_throw (ctx, error_message);
  }
#endif
}

JSValue
_gum_quick_native_pointer_new (gpointer address,
                               GumQuickCore * core)
{
  return JS_UNDEFINED; /* TODO */
}

gboolean
_gum_quick_native_pointer_get (JSValueConst value,
                               gpointer * ptr,
                               GumQuickCore * core)
{
  return FALSE; /* TODO */
}

gboolean
_gum_quick_native_pointer_parse (JSValueConst value,
                                 gpointer * ptr,
                                 GumQuickCore * core)
{
  return FALSE; /* TODO */
}
