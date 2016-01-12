/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukvalue.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

#define GUM_MAX_JS_BYTE_ARRAY_LENGTH (100 * 1024 * 1024)

static const gchar * gum_exception_type_to_string (GumExceptionType type);

void
_gum_duk_args_parse (const GumDukArgs * args,
                     const gchar * format,
                     ...)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = args->core;
  va_list ap;
  guint arg_index;
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

    if (arg_index >= duk_get_top (ctx) || duk_is_undefined (ctx, arg_index))
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
        if (!duk_is_number (ctx, arg_index))
          goto expected_int;

        *va_arg (ap, gint *) = duk_require_int (ctx, arg_index);

        break;
      }
      case 'u':
      {
        guint u;

        if (!_gum_duk_get_uint (ctx, arg_index, &u))
          goto expected_uint;

        *va_arg (ap, guint *) = (guint) u;

        break;
      }
      case 'n':
      {
        if (!duk_is_number (ctx, arg_index))
          goto expected_number;

        *va_arg (ap, gdouble *) = duk_require_number (ctx, arg_index);

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
          if (!_gum_duk_parse_pointer (ctx, arg_index, core, &ptr))
            goto expected_pointer;
        }
        else
        {
          if (!_gum_duk_get_pointer (ctx, arg_index, core, &ptr))
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

        if (is_nullable && duk_is_null (ctx, arg_index))
          str = NULL;
        else if ((str = duk_get_string (ctx, arg_index)) == NULL)
          goto expected_string;

        *va_arg (ap, const gchar **) = str;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_duk_parse_protection (ctx, arg_index, &prot))
          goto expected_protection;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        GumDukHeapPtr value;

        value = duk_get_heapptr (ctx, arg_index);
        if (value == NULL)
          goto expected_heap_pointer;

        *va_arg (ap, GumDukHeapPtr *) = value;

        break;
      }
      case 'O':
      {
        if (!duk_is_object (ctx, arg_index))
          goto expected_object;

        *va_arg (ap, GumDukHeapPtr *) = duk_require_heapptr (ctx, arg_index);

        break;
      }
      case 'A':
      {
        GumDukHeapPtr array;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (duk_is_array (ctx, arg_index))
          array = duk_require_heapptr (ctx, arg_index);
        else if (is_nullable && duk_is_null (ctx, arg_index))
          array = NULL;
        else
          goto expected_array;

        *va_arg (ap, GumDukHeapPtr *) = array;

        break;
      }
      case 'F':
      {
        GumDukHeapPtr func;
        gboolean is_expecting_object, is_nullable;

        is_expecting_object = t[1] == '{';
        if (is_expecting_object)
          t += 2;

        if (is_expecting_object)
        {
          const gchar * next, * end, * t_end;

          if (!duk_is_object (ctx, arg_index))
            goto expected_callback_object;

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

            duk_get_prop_string (ctx, arg_index, name);
            if (duk_is_function (ctx, -1))
            {
              func = duk_require_heapptr (ctx, -1);
            }
            else if (is_nullable && duk_is_null_or_undefined (ctx, -1))
            {
              func = NULL;
            }
            else
            {
              duk_pop (ctx);
              goto expected_callback_value;
            }
            duk_pop (ctx);

            *va_arg (ap, GumDukHeapPtr *) = func;

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

          if (duk_is_function (ctx, arg_index))
            func = duk_require_heapptr (ctx, arg_index);
          else if (is_nullable && duk_is_null (ctx, arg_index))
            func = NULL;
          else
            goto expected_function;

          *va_arg (ap, GumDukHeapPtr *) = func;
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

        if (is_nullable && duk_is_null (ctx, arg_index))
          bytes = NULL;
        else if (!_gum_duk_parse_bytes (ctx, arg_index, &bytes))
          goto expected_bytes;

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

        if (is_nullable && duk_is_null (ctx, arg_index))
          cpu_context = NULL;
        else if ((cpu_context = _gum_duk_get_cpu_context (ctx, arg_index,
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
error:
  {
    va_end (ap);

    g_slist_foreach (byte_arrays, (GFunc) g_bytes_unref, NULL);
    g_slist_free (byte_arrays);

    g_assert (error_message != NULL);
    _gum_duk_throw (ctx, error_message);
  }
}

gpointer
_gum_duk_get_data (duk_context * ctx,
                   duk_idx_t index)
{
  gpointer result;

  duk_get_prop_string (ctx, index, "\xff" "priv");
  if (!duk_is_undefined (ctx, -1))
    result = duk_require_pointer (ctx, -1);
  else
    result = NULL;
  duk_pop (ctx);

  return result;
}

gpointer
_gum_duk_require_data (duk_context * ctx,
                       duk_idx_t index)
{
  gpointer result;

  duk_get_prop_string (ctx, index, "\xff" "priv");
  result = duk_require_pointer (ctx, -1);
  duk_pop (ctx);

  return result;
}

void
_gum_duk_put_data (duk_context * ctx,
                   duk_idx_t index,
                   gpointer data)
{
  duk_dup (ctx, index);
  duk_push_pointer (ctx, data);
  duk_put_prop_string (ctx, -2, "\xff" "priv");
  duk_pop (ctx);
}

gpointer
_gum_duk_steal_data (duk_context * ctx,
                     duk_idx_t index)
{
  gpointer result = NULL;

  duk_get_prop_string (ctx, index, "\xff" "priv");
  if (!duk_is_undefined (ctx, -1))
  {
    result = duk_require_pointer (ctx, -1);
    duk_pop (ctx);

    duk_push_pointer (ctx, NULL);
    duk_put_prop_string (ctx, index, "\xff" "priv");
  }
  else
  {
    duk_pop (ctx);
  }

  return result;
}

guint
_gum_duk_require_index (duk_context * ctx,
                        duk_idx_t index)
{
  if (duk_is_number (ctx, index))
  {
    guint value;

    if (_gum_duk_get_uint (ctx, index, &value))
    {
      return value;
    }
    else
    {
      _gum_duk_throw (ctx, "invalid index");
      return 0; /* unreachable */
    }
  }
  else
  {
    const gchar * str;
    gchar * endptr;
    glong value;
    gboolean valid;

    str = duk_require_string (ctx, index);

    value = strtol (str, &endptr, 10);

    valid = *str != '\0' && *endptr == '\0' && value >= 0;
    if (!valid)
      _gum_duk_throw (ctx, "invalid index");

    return value;
  }
}

gboolean
_gum_duk_get_uint (duk_context * ctx,
                   duk_idx_t index,
                   guint * u)
{
  duk_double_t number;

  if (!duk_is_number (ctx, index))
    return FALSE;

  number = duk_require_number (ctx, index);
  if (number < 0)
    return FALSE;

  *u = (guint) number;
  return TRUE;
}

gboolean
_gum_duk_get_int64 (duk_context * ctx,
                    duk_idx_t index,
                    gint64 * i)
{
  if (!duk_is_number (ctx, index))
    return FALSE;

  *i = (gint64) duk_require_number (ctx, index);
  return TRUE;
}

gboolean
_gum_duk_get_uint64 (duk_context * ctx,
                     duk_idx_t index,
                     guint64 * u)
{
  duk_double_t number;

  if (!duk_is_number (ctx, index))
    return FALSE;

  number = duk_require_number (ctx, index);
  if (number < 0)
    return FALSE;

  *u = (guint64) number;
  return TRUE;
}

gboolean
_gum_duk_get_pointer (duk_context * ctx,
                      duk_idx_t index,
                      GumDukCore * core,
                      gpointer * ptr)
{
  gboolean success = TRUE;

  duk_dup (ctx, index);
  duk_push_heapptr (ctx, core->native_pointer);

  if (duk_is_pointer (ctx, -2))
  {
    *ptr = duk_require_pointer (ctx, -2);
  }
  else if (duk_instanceof (ctx, -2, -1))
  {
    GumDukNativePointer * p;

    p = _gum_duk_require_data (ctx, -2);

    *ptr = p->value;
  }
  else if (duk_is_object (ctx, -2))
  {
    gboolean is_native_pointer;

    duk_get_prop_string (ctx, -2, "handle");

    is_native_pointer = duk_instanceof (ctx, -1, -2);
    if (is_native_pointer)
    {
      GumDukNativePointer * p;

      p = _gum_duk_require_data (ctx, -1);

      *ptr = p->value;
    }
    else
    {
      success = FALSE;
    }

    duk_pop (ctx);
  }
  else
  {
    success = FALSE;
  }

  duk_pop_2 (ctx);

  return success;
}

gboolean
_gum_duk_parse_pointer (duk_context * ctx,
                        duk_idx_t index,
                        GumDukCore * core,
                        gpointer * ptr)
{
  if (duk_is_string (ctx, index))
  {
    const gchar * ptr_as_string, * end;
    gboolean valid;

    ptr_as_string = duk_require_string (ctx, index);

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

    return valid;
  }
  else if (duk_is_number (ctx, index))
  {
    duk_double_t number;

    number = duk_require_number (ctx, index);
    if (number < 0)
      return FALSE;

    *ptr = GSIZE_TO_POINTER ((gsize) number);
    return TRUE;
  }

  return _gum_duk_get_pointer (ctx, index, core, ptr);
}

gboolean
_gum_duk_parse_protection (duk_context * ctx,
                           duk_idx_t index,
                           GumPageProtection * prot)
{
  const gchar * prot_str, * ch;

  if (!duk_is_string (ctx, index))
    return FALSE;

  prot_str = duk_require_string (ctx, index);

  *prot = GUM_PAGE_NO_ACCESS;
  for (ch = prot_str; *ch != '\0'; ch++)
  {
    switch (*ch)
    {
      case 'r':
        *prot |= GUM_PAGE_READ;
        break;
      case 'w':
        *prot |= GUM_PAGE_WRITE;
        break;
      case 'x':
        *prot |= GUM_PAGE_EXECUTE;
        break;
      case '-':
        break;
      default:
        return FALSE;
    }
  }

  return TRUE;
}

gboolean
_gum_duk_parse_bytes (duk_context * ctx,
                      duk_idx_t index,
                      GBytes ** bytes)
{
  gpointer data;
  duk_size_t size;

  data = duk_get_buffer_data (ctx, index, &size);
  if (data != NULL)
  {
    *bytes = g_bytes_new (data, size);
    return TRUE;
  }
  else if (duk_is_array (ctx, index))
  {
    duk_size_t i;

    duk_get_prop_string (ctx, index, "length");
    size = duk_get_uint (ctx, -1);
    duk_pop (ctx);

    if (size >= GUM_MAX_JS_BYTE_ARRAY_LENGTH)
      return FALSE;

    data = g_malloc (size);

    for (i = 0; i != size; i++)
    {
      duk_get_prop_index (ctx, index, i);
      ((guint8 *) data)[i] = duk_get_uint (ctx, -1) & 0xff;
      duk_pop (ctx);
    }

    *bytes = g_bytes_new_take (data, size);
    return TRUE;
  }
  else if (duk_is_null_or_undefined (ctx, index) ||
      duk_is_boolean (ctx, index) ||
      duk_is_number (ctx, index) ||
      duk_is_nan (ctx, index) ||
      duk_is_string (ctx, index) ||
      duk_is_function (ctx, index))
  {
    return FALSE;
  }

  *bytes = g_bytes_new (NULL, 0);
  return TRUE;
}

void
_gum_duk_push_native_pointer (duk_context * ctx,
                              gpointer address,
                              GumDukCore * core)
{
  GumDukNativePointerImpl * ptr;

  ptr = core->cached_native_pointers;
  if (ptr != NULL)
  {
    core->cached_native_pointers = ptr->next;

    duk_push_heapptr (ctx, ptr->object);
    ptr->parent.value = address;

    duk_push_global_stash (ctx);
    duk_del_prop_string (ctx, -1, ptr->id);
    duk_pop (ctx);

    return;
  }

  duk_push_heapptr (ctx, core->native_pointer);
  duk_push_pointer (ctx, address);
  duk_new (ctx, 1);
}

GumDukNativePointer *
_gum_duk_require_native_pointer (duk_context * ctx,
                                 duk_idx_t index,
                                 GumDukCore * core)
{
  duk_dup (ctx, index);
  duk_push_heapptr (ctx, core->native_pointer);
  if (!duk_instanceof (ctx, -2, -1))
    _gum_duk_throw (ctx, "expected NativePointer");
  duk_pop_2 (ctx);

  return _gum_duk_require_data (ctx, index);
}

void
_gum_duk_push_native_resource (duk_context * ctx,
                               gpointer data,
                               GDestroyNotify notify,
                               GumDukCore * core)
{
  duk_push_heapptr (ctx, core->native_resource);
  duk_push_pointer (ctx, data);
  duk_push_pointer (ctx, notify);
  duk_new (ctx, 2);
}

GumDukCpuContext *
_gum_duk_push_cpu_context (duk_context * ctx,
                           GumCpuContext * handle,
                           GumDukCpuContextAccess access,
                           GumDukCore * core)
{
  GumDukCpuContext * scc;

  scc = g_slice_new (GumDukCpuContext);

  duk_push_heapptr (ctx, core->cpu_context);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, scc);
  scc->object = duk_require_heapptr (ctx, -1);

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

  return scc;
}

GumCpuContext *
_gum_duk_get_cpu_context (duk_context * ctx,
                          duk_idx_t index,
                          GumDukCore * core)
{
  gboolean is_cpu_context;
  GumDukCpuContext * instance;

  if (!duk_is_object (ctx, index))
    return NULL;

  duk_dup (ctx, index);
  duk_push_heapptr (ctx, core->cpu_context);
  is_cpu_context = duk_instanceof (ctx, -2, -1);
  duk_pop_2 (ctx);

  if (!is_cpu_context)
    return NULL;

  instance = _gum_duk_require_data (ctx, index);

  return instance->handle;
}

void
_gum_duk_cpu_context_make_read_only (GumDukCpuContext * self)
{
  if (self->access == GUM_CPU_CONTEXT_READWRITE)
  {
    memcpy (&self->storage, self->handle, sizeof (GumCpuContext));
    self->handle = &self->storage;
    self->access = GUM_CPU_CONTEXT_READONLY;
  }
}

void
_gum_duk_push_exception_details (duk_context * ctx,
                                 GumExceptionDetails * details,
                                 GumDukCore * core,
                                 GumDukCpuContext ** cpu_context)
{
  const GumExceptionMemoryDetails * md = &details->memory;
  gchar * message;

  message = gum_exception_details_to_string (details);
  duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", message);
  g_free (message);

  duk_push_string (ctx, gum_exception_type_to_string (details->type));
  duk_put_prop_string (ctx, -2, "type");
  duk_push_pointer (ctx, details->address);
  duk_put_prop_string (ctx, -2, "address");

  if (md->operation != GUM_MEMOP_INVALID)
  {
    duk_push_object (ctx);

    duk_push_string (ctx, _gum_duk_memory_operation_to_string (md->operation));
    duk_put_prop_string (ctx, -2, "operation");
    duk_push_pointer (ctx, md->address);
    duk_put_prop_string (ctx, -2, "address");

    duk_put_prop_string (ctx, -2, "memory");
  }

  *cpu_context = _gum_duk_push_cpu_context (ctx, &details->context,
      GUM_CPU_CONTEXT_READWRITE, core);
  duk_put_prop_string (ctx, -2, "context");
  duk_push_pointer (ctx, details->native_context);
  duk_put_prop_string (ctx, -2, "nativeContext");
}

void
_gum_duk_push_proxy (duk_context * ctx,
                     duk_idx_t target,
                     duk_c_function getter,
                     duk_c_function setter)
{
  duk_dup (ctx, target);

  duk_get_global_string (ctx, "Proxy");
  duk_dup (ctx, -2);
  duk_push_object (ctx);

  if (getter != NULL)
  {
    duk_push_c_function (ctx, getter, 3);
    duk_put_prop_string (ctx, -2, "get");
  }

  if (setter != NULL)
  {
    duk_push_c_function (ctx, setter, 4);
    duk_put_prop_string (ctx, -2, "set");
  }

  duk_new (ctx, 2);

  duk_swap_top (ctx, -2);
  duk_pop (ctx);
}

void
_gum_duk_throw (duk_context * ctx,
                const gchar * format,
                ...)
{
  va_list ap;

  va_start (ap, format);
  duk_push_error_object_va (ctx, DUK_ERR_ERROR, format, ap);
  va_end (ap);

  duk_throw (ctx);
}

void
_gum_duk_throw_native (duk_context * ctx,
                       GumExceptionDetails * details,
                       GumDukCore * core)
{
  GumDukCpuContext * cc;

  _gum_duk_push_exception_details (ctx, details, core, &cc);
  _gum_duk_cpu_context_make_read_only (cc);
  duk_throw (ctx);
}

void
_gum_duk_create_subclass (duk_context * ctx,
                          const gchar * parent,
                          const gchar * name,
                          gpointer constructor,
                          gint constructor_nargs,
                          gpointer finalize)
{
  duk_push_global_object (ctx);
  duk_get_prop_string (ctx, -1, "Object");
  duk_get_prop_string (ctx, -1, "create");

  duk_get_prop_string (ctx, -3, parent);
  duk_get_prop_string (ctx, -1, "prototype");
  duk_dup (ctx, -3);
  duk_dup (ctx, -2);
  duk_call (ctx, 1);

  if (constructor != NULL)
    duk_push_c_function (ctx, constructor, constructor_nargs);
  else
    duk_push_object (ctx);

  duk_dup (ctx, -2);
  if (finalize != NULL)
  {
    duk_push_c_function (ctx, finalize, 2);
    duk_set_finalizer (ctx, -2);
  }
  duk_put_prop_string (ctx, -2, "prototype");
  duk_put_prop_string (ctx, -7, name);
  duk_pop_n (ctx, 6);
}

void
_gum_duk_add_properties_to_class_by_heapptr (
    duk_context * ctx,
    GumDukHeapPtr klass,
    const GumDukPropertyEntry * entries)
{
  const GumDukPropertyEntry * entry;

  duk_push_heapptr (ctx, klass);

  for (entry = entries; entry->name != NULL; entry++)
  {
    int idx = 1;
    int flags = DUK_DEFPROP_HAVE_ENUMERABLE | DUK_DEFPROP_ENUMERABLE;

    duk_push_string (ctx, entry->name);
    idx++;

    if (entry->getter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_GETTER;
      duk_push_c_function (ctx, entry->getter, 0);
    }

    if (entry->setter != NULL)
    {
      idx++;
      flags |= DUK_DEFPROP_HAVE_SETTER;
      duk_push_c_function (ctx, entry->setter, 1);
    }

    duk_def_prop (ctx, -idx, flags);
  }

  duk_pop (ctx);
}

void
_gum_duk_add_properties_to_class (duk_context * ctx,
                                  const gchar * class_name,
                                  const GumDukPropertyEntry * entries)
{
  duk_get_global_string (ctx, class_name);
  duk_get_prop_string (ctx, -1, "prototype");
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), entries);
  duk_pop_2 (ctx);
}

gboolean
_gum_duk_is_arg0_equal_to_prototype (duk_context * ctx,
                                     const gchar * class_name)
{
  gboolean result;

  duk_get_global_string (ctx, class_name);
  duk_get_prop_string (ctx, -1, "prototype");
  result = duk_equals (ctx, 0, -1);
  duk_pop_2 (ctx);

  return result;
}

void
_gum_duk_protect (duk_context * ctx,
                  GumDukHeapPtr object)
{
  gchar name[256];
  duk_uint_t ref_count;

  sprintf (name, "protected_%p", object);

  duk_push_global_stash (ctx);

  duk_get_prop_string (ctx, -1, name);
  if (duk_is_undefined (ctx, -1))
  {
    duk_pop (ctx);

    duk_push_object (ctx);
    duk_push_heapptr (ctx, object);
    duk_put_prop_string (ctx, -2, "o");
    ref_count = 1;
    duk_push_uint (ctx, ref_count);
    duk_put_prop_string (ctx, -2, "n");

    duk_put_prop_string (ctx, -2, name);
  }
  else
  {
    duk_get_prop_string (ctx, -1, "n");
    ref_count = duk_get_uint (ctx, -1);
    duk_pop (ctx);
    ref_count++;
    duk_push_uint (ctx, ref_count);
    duk_put_prop_string (ctx, -2, "n");

    duk_pop (ctx);
  }

  duk_pop (ctx);
}

void
_gum_duk_unprotect (duk_context * ctx,
                    GumDukHeapPtr object)
{
  gchar name[256];
  duk_uint_t ref_count;

  sprintf (name, "protected_%p", object);

  duk_push_global_stash (ctx);

  duk_get_prop_string (ctx, -1, name);
  g_assert (!duk_is_undefined (ctx, -1));

  duk_get_prop_string (ctx, -1, "n");
  ref_count = duk_get_uint (ctx, -1);
  duk_pop (ctx);
  ref_count--;
  if (ref_count == 0)
  {
    duk_pop (ctx);

    duk_del_prop_string (ctx, -1, name);
  }
  else
  {
    duk_push_uint (ctx, ref_count);
    duk_put_prop_string (ctx, -2, "n");

    duk_pop (ctx);
  }

  duk_pop (ctx);
}

GumDukHeapPtr
_gum_duk_require_heapptr (duk_context * ctx,
                          gint idx)
{
  GumDukHeapPtr result;

  result = duk_require_heapptr (ctx, idx);
  _gum_duk_protect (ctx, result);

  return result;
}

void
_gum_duk_release_heapptr (duk_context * ctx,
                          GumDukHeapPtr heapptr)
{
  _gum_duk_unprotect (ctx, heapptr);
}

GumDukWeakRef *
_gum_duk_weak_ref_new (duk_context * ctx,
                       GumDukHeapPtr value,
                       GumDukWeakNotify notify,
                       gpointer data,
                       GDestroyNotify data_destroy)
{
  /* TODO: implement */
  return NULL;
}

void
_gum_duk_weak_ref_free (GumDukWeakRef * ref)
{
  /* TODO: implement */
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

const gchar *
_gum_duk_thread_state_to_string (GumThreadState state)
{
  switch (state)
  {
    case GUM_THREAD_RUNNING: return "running";
    case GUM_THREAD_STOPPED: return "stopped";
    case GUM_THREAD_WAITING: return "waiting";
    case GUM_THREAD_UNINTERRUPTIBLE: return "uninterruptible";
    case GUM_THREAD_HALTED: return "halted";
    default:
      break;
  }

  g_assert_not_reached ();
}

const gchar *
_gum_duk_memory_operation_to_string (GumMemoryOperation operation)
{
  switch (operation)
  {
    case GUM_MEMOP_INVALID: return "invalid";
    case GUM_MEMOP_READ: return "read";
    case GUM_MEMOP_WRITE: return "write";
    case GUM_MEMOP_EXECUTE: return "execute";
    default:
      g_assert_not_reached ();
  }
}
