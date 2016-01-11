/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukvalue.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

#define GUM_MAX_JS_BYTE_ARRAY_LENGTH (100 * 1024 * 1024)

static void gum_native_resource_on_weak_notify (
    GumDukNativeResource * resource);

static const gchar * gum_exception_type_to_string (GumExceptionType type);

void
_gum_duk_require_args (duk_context * ctx,
                       const gchar * format,
                       ...)
{
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

        *va_arg (ap, gint *) = duk_get_int (ctx, arg_index);

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

        *va_arg (ap, gdouble *) = duk_get_number (ctx, arg_index);

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
          if (!_gum_duk_parse_pointer (ctx, arg_index, &ptr))
            goto expected_pointer;
        }
        else
        {
          if (!_gum_duk_get_pointer (ctx, arg_index, &ptr))
            goto expected_pointer;
        }

        *va_arg (ap, gpointer *) = ptr;

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
      case 's':
      {
        const gchar * str;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable)
        {
          if (duk_is_null (ctx, arg_index))
            str = NULL;
          else
            str = duk_get_string (ctx, arg_index);
        }
        else
        {
          str = duk_get_string (ctx, arg_index);
        }

        *va_arg (ap, const gchar **) = str;

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

        *va_arg (ap, GumDukHeapPtr *) = duk_get_heapptr (ctx, arg_index);

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
          array = duk_get_heapptr (ctx, arg_index);
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
              func = duk_get_heapptr (ctx, -1);
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
            func = duk_get_heapptr (ctx, arg_index);
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
        else if (!_gum_duk_get_cpu_context (ctx, arg_index, &cpu_context))
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
    _gumjs_throw (ctx, error_message);
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

  number = duk_get_number (ctx, index);
  if (number < 0)
    return FALSE;

  *u = (guint) number;
  return TRUE;
}

gboolean
_gum_duk_get_pointer (duk_context * ctx,
                      duk_idx_t index,
                      gpointer * ptr)
{
  GumDukHeapPtr object;

  object = duk_get_heapptr (ctx, index);
  if (_gumjs_is_instanceof (ctx, object, "NativePointer"))
  {
    *ptr = _gumjs_native_pointer_value (ctx, object);
  }
  else if (duk_is_object (ctx, index))
  {
    GumDukHeapPtr handle;

    duk_get_prop_string (ctx, index, "handle");
    handle = duk_get_heapptr (ctx, -1);
    duk_pop (ctx);

    if (_gumjs_is_instanceof (ctx, handle, "NativePointer"))
      *ptr = _gumjs_native_pointer_value (ctx, handle);
    else
      return FALSE;
  }
  else if (duk_is_pointer (ctx, index))
  {
    *ptr = duk_get_pointer (ctx, index);
  }
  else
  {
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_duk_parse_pointer (duk_context * ctx,
                        duk_idx_t index,
                        gpointer * ptr)
{
  if (duk_is_string (ctx, index))
  {
    const gchar * ptr_as_string, * end;
    gboolean valid;

    ptr_as_string = duk_get_string (ctx, index);

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

    number = duk_get_number (ctx, index);
    if (number < 0)
      return FALSE;

    *ptr = GSIZE_TO_POINTER ((gsize) number);
    return TRUE;
  }

  return _gum_duk_get_pointer (ctx, index, ptr);
}

gboolean
_gum_duk_parse_protection (duk_context * ctx,
                           duk_idx_t index,
                           GumPageProtection * prot)
{
  const gchar * prot_str, * ch;

  if (!duk_is_string (ctx, index))
    return FALSE;

  prot_str = duk_get_string (ctx, index);

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

gboolean
_gum_duk_get_cpu_context (duk_context * ctx,
                          duk_idx_t index,
                          GumCpuContext ** cpu_context)
{
  gboolean is_cpu_context;
  GumDukCpuContext * instance;

  if (!duk_is_object (ctx, index))
    return FALSE;

  duk_get_global_string (ctx, "CpuContext");
  is_cpu_context = duk_instanceof (ctx, index, -1);
  duk_pop (ctx);

  if (!is_cpu_context)
    return FALSE;

  instance = _gumjs_get_private_data (ctx, duk_get_heapptr (ctx, index));

  *cpu_context = instance->handle;
  return TRUE;
}

GumDukValue *
_gumjs_object_get (duk_context * ctx,
                   GumDukHeapPtr object,
                   const gchar * key)
{
  GumDukValue * value;

  duk_push_heapptr (ctx, object);
  duk_get_prop_string (ctx, -1, key);

  value = _gumjs_get_value (ctx, -1);

  duk_pop_2 (ctx);

  return value;
}

GumDukHeapPtr
_gumjs_native_pointer_new (duk_context * ctx,
                           gpointer address,
                           GumDukCore * core)
{
  GumDukHeapPtr result;

  duk_push_heapptr (ctx, core->native_pointer);
  duk_push_pointer (ctx, address);
  duk_new (ctx, 1);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}

void
_gumjs_native_pointer_push (duk_context * ctx,
                            gpointer address,
                            GumDukCore * core)
{
  duk_push_heapptr (ctx, core->native_pointer);
  duk_push_pointer (ctx, address);
  duk_new (ctx, 1);
}

gpointer
_gumjs_native_pointer_value (duk_context * ctx,
                             GumDukHeapPtr value)
{
  GumDukNativePointer * ptr;

  ptr = _gumjs_get_private_data (ctx, value);
  g_assert (ptr != NULL);

  return ptr->value;
}

GumDukHeapPtr
_gumjs_cpu_context_new (duk_context * ctx,
                        GumCpuContext * handle,
                        GumDukCpuContextAccess access,
                        GumDukCore * core)
{
  GumDukCpuContext * scc;
  GumDukHeapPtr result;
  gint res;

  scc = g_slice_new (GumDukCpuContext);
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

  duk_get_global_string (ctx, "CpuContext");
  res = duk_pnew (ctx, 0);
  g_assert (res == 0);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gumjs_set_private_data (ctx, result, scc);

  return result;
}

gpointer
_gumjs_get_private_data (duk_context * ctx,
                         GumDukHeapPtr object)
{
  gpointer result;

  duk_push_heapptr (ctx, object);
  duk_get_prop_string (ctx, -1, "\xff" "priv");
  if (duk_is_undefined (ctx, -1))
    result = NULL;
  else
    result = duk_get_pointer (ctx, -1);
  duk_pop_2 (ctx);

  return result;
}

gpointer
_gumjs_steal_private_data (duk_context * ctx,
                           GumDukHeapPtr object)
{
  gpointer result = NULL;

  duk_push_heapptr (ctx, object);

  duk_get_prop_string (ctx, -1, "\xff" "priv");
  if (!duk_is_undefined (ctx, -1))
  {
    result = duk_get_pointer (ctx, -1);
    duk_pop (ctx);

    duk_push_pointer (ctx, NULL);
    duk_put_prop_string (ctx, -2, "\xff" "priv");

    duk_pop (ctx);
  }
  else
  {
    duk_pop_2 (ctx);
  }

  return result;
}

void
_gumjs_set_private_data (duk_context * ctx,
                         GumDukHeapPtr object,
                         gpointer data)
{
  duk_push_heapptr (ctx, object);
  duk_push_pointer (ctx, data);
  duk_put_prop_string (ctx, -2, "\xff" "priv");
  duk_pop (ctx);
}

void
_gumjs_cpu_context_detach (duk_context * ctx,
                           GumDukHeapPtr value)
{
  GumDukCpuContext * self;

  duk_push_heapptr (ctx, value);

  self = _gumjs_get_private_data (ctx, value);

  if (self->access == GUM_CPU_CONTEXT_READWRITE)
  {
    memcpy (&self->storage, self->handle, sizeof (GumCpuContext));
    self->handle = &self->storage;
    self->access = GUM_CPU_CONTEXT_READONLY;
  }
}

GumDukNativeResource *
_gumjs_native_resource_new (duk_context * ctx,
                            gpointer data,
                            GDestroyNotify notify,
                            GumDukCore * core,
                            GumDukHeapPtr * handle)
{
  GumDukHeapPtr h;
  GumDukNativeResource * resource;

  h = _gumjs_native_pointer_new (ctx, data, core);

  resource = g_slice_new (GumDukNativeResource);
  resource->weak_ref = _gumjs_weak_ref_new (ctx, h,
      (GumDukWeakNotify) gum_native_resource_on_weak_notify, resource, NULL);
  resource->data = data;
  resource->notify = notify;
  resource->core = core;

  g_hash_table_insert (core->native_resources, resource, resource);

  *handle = h;

  return resource;
}

void
_gumjs_native_resource_free (GumDukNativeResource * resource)
{
  _gumjs_weak_ref_free (resource->weak_ref);

  if (resource->notify != NULL)
    resource->notify (resource->data);

  g_slice_free (GumDukNativeResource, resource);
}

static void
gum_native_resource_on_weak_notify (GumDukNativeResource * self)
{
  GumDukCore * core = self->core;

  GUM_DUK_CORE_LOCK (core);
  g_hash_table_remove (core->native_resources, self);
  GUM_DUK_CORE_UNLOCK (core);
}

GumDukHeapPtr
_gumjs_array_buffer_new (duk_context * ctx,
                         gsize size,
                         GumDukCore * core)
{
  GumDukHeapPtr result;

  duk_get_global_string (ctx, "ArrayBuffer");
  duk_push_int (ctx, size);
  duk_new (ctx, 1);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}

gboolean
_gumjs_array_buffer_try_get_data (duk_context * ctx,
                                  GumDukHeapPtr value,
                                  gpointer * data,
                                  gsize * size)
{
  duk_push_heapptr (ctx, value);
  *data = duk_get_buffer_data (ctx, -1, size);
  duk_pop (ctx);

  return TRUE;
}

gpointer
_gumjs_array_buffer_get_data (duk_context * ctx,
                              GumDukHeapPtr value,
                              gsize * size)
{
  gpointer data;

  if (!_gumjs_array_buffer_try_get_data (ctx, value, &data, size))
    _gumjs_panic (ctx, "failed to get ArrayBuffer data");

  return data;
}

void
_gumjs_throw (duk_context * ctx,
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
_gumjs_throw_native (duk_context * ctx,
                     GumExceptionDetails * details,
                     GumDukCore * core)
{
  GumDukHeapPtr ex, cc;

  _gumjs_parse_exception_details (ctx, details, core, &ex, &cc);
  _gumjs_cpu_context_detach (ctx, cc);

  duk_push_heapptr (ctx, ex);
  _gumjs_duk_release_heapptr (ctx, ex);
  duk_throw (ctx);
}

void
_gumjs_parse_exception_details (duk_context * ctx,
                                GumExceptionDetails * details,
                                GumDukCore * core,
                                GumDukHeapPtr * exception,
                                GumDukHeapPtr * cpu_context)
{
  const GumExceptionMemoryDetails * md = &details->memory;
  gchar * message;
  GumDukHeapPtr ex, cc;

  message = gum_exception_details_to_string (details);
  duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", message);
  g_free (message);
  ex = _gumjs_duk_get_heapptr (ctx, -1);

  duk_push_string (ctx, gum_exception_type_to_string (details->type));
  duk_put_prop_string (ctx, -2, "type");
  duk_push_pointer (ctx, details->address);
  duk_put_prop_string (ctx, -2, "address");

  if (md->operation != GUM_MEMOP_INVALID)
  {
    duk_push_object (ctx);
    duk_push_string (ctx, _gumjs_memory_operation_to_string (md->operation));
    duk_put_prop_string (ctx, -2, "operation");
    duk_push_pointer (ctx, md->address);
    duk_put_prop_string (ctx, -2, "address");
    duk_put_prop_string (ctx, -2, "memory");
  }

  cc = _gumjs_cpu_context_new (ctx, &details->context,
      GUM_CPU_CONTEXT_READWRITE, core);
  duk_push_heapptr (ctx, cc);
  duk_put_prop_string (ctx, -2, "context");
  duk_push_pointer (ctx, details->native_context);
  duk_put_prop_string (ctx, -2, "nativeContext");

  duk_pop (ctx);
  *exception = ex;
  *cpu_context = cc;
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
_gumjs_thread_state_to_string (GumThreadState state)
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
_gumjs_memory_operation_to_string (GumMemoryOperation operation)
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

gboolean
_gumjs_value_string_try_get (duk_context * ctx,
                             GumDukValue * value,
                             gchar ** str)
{
  if (!_gumjs_value_string_try_get_opt (ctx, value, str))
    return FALSE;

  if (*str == NULL)
    goto string_required;

  return TRUE;

string_required:
  {
    _gumjs_throw (ctx, "string required");
    return FALSE;
  }
}

gboolean
_gumjs_value_string_try_get_opt (duk_context * ctx,
                                 GumDukValue * value,
                                 gchar ** str)
{
  if (value->type != DUK_TYPE_UNDEFINED && value->type != DUK_TYPE_NULL)
  {

    if (value->type != DUK_TYPE_STRING)
      goto invalid_type;

    *str = (gchar *) value->data._string;
    if (*str == NULL)
      return FALSE;
  }
  else
  {
    *str = NULL;
  }

  return TRUE;

invalid_type:
  {
    _gumjs_throw (ctx, "expected a string");
    return FALSE;
  }
}

gboolean
_gumjs_byte_array_try_get (duk_context * ctx,
                           GumDukValue * value,
                           GBytes ** bytes)
{
  if (!_gumjs_byte_array_try_get_opt (ctx, value, bytes))
    return FALSE;

  if (*bytes == NULL)
    goto byte_array_required;

  return TRUE;

byte_array_required:
  {
    _gumjs_throw (ctx, "byte array required");
    return FALSE;
  }
}

gboolean
_gumjs_byte_array_try_get_opt (duk_context * ctx,
                               GumDukValue * value,
                               GBytes ** bytes)
{
  gpointer buffer_data;
  gsize buffer_size, i;
  guint8 * data;

  if (value->type == DUK_TYPE_UNDEFINED || value->type == DUK_TYPE_NULL)
  {
    *bytes = NULL;
    return FALSE;
  }
  else if (value->type == DUK_TYPE_OBJECT)
  {
    if (_gumjs_is_instanceof (ctx, value->data._heapptr, "ArrayBuffer"))
    {
      _gumjs_array_buffer_try_get_data (ctx, value->data._heapptr,
          &buffer_data, &buffer_size);
      *bytes = g_bytes_new (buffer_data, buffer_size);
    }
    else
    {
      duk_push_heapptr (ctx, value->data._heapptr);
      duk_get_prop_string (ctx, -1, "length");
      buffer_size = duk_get_uint (ctx, -1);
      duk_pop (ctx);
      data = g_malloc (buffer_size);
      for (i = 0; i < buffer_size; i++)
      {
        duk_get_prop_index (ctx, -1, i);
        data[i] = (guint8) duk_require_uint (ctx, -1);
        duk_pop (ctx);
      }
      duk_pop (ctx);
      *bytes = g_bytes_new_take (data, buffer_size);
    }

    return TRUE;
  }

  *bytes = NULL;
  return FALSE;
}

gboolean
_gumjs_value_is_object_of_class (duk_context * ctx,
                                 GumDukValue * value,
                                 const gchar * class_name)
{
  gboolean result = FALSE;
  if (value->type != DUK_TYPE_OBJECT)
    return result;

  duk_push_heapptr (ctx, value->data._heapptr);
  duk_get_global_string (ctx, class_name);
  result = duk_instanceof (ctx, -2, -1);
  duk_pop_2 (ctx);
  return result;
}

gboolean
_gumjs_object_try_get (duk_context * ctx,
                       GumDukHeapPtr object,
                       const gchar * key,
                       GumDukValue ** value)
{
  duk_push_heapptr (ctx, object);
  duk_get_prop_string (ctx, -1, key);
  *value = _gumjs_get_value (ctx, -1);
  duk_pop_2 (ctx);
  return *value != NULL;
}

gboolean
_gumjs_value_native_pointer_try_get (duk_context * ctx,
                                     GumDukValue * value,
                                     GumDukCore * core,
                                     gpointer * target)
{
  GumDukValue * handle = NULL;

  if (_gumjs_value_is_object_of_class (ctx, value, "NativePointer"))
  {
    *target = _gumjs_native_pointer_value (ctx, value->data._heapptr);
    return TRUE;
  }
  else if (value->type == DUK_TYPE_OBJECT && _gumjs_object_try_get (ctx,
        value->data._heapptr, "handle", &handle) &&
      _gumjs_value_is_object_of_class (ctx, handle, "NativePointer"))
  {
    *target = _gumjs_native_pointer_value (ctx, handle->data._heapptr);
    g_free (handle);
    return TRUE;
  }
  else
  {
    if (handle != NULL)
      g_free (handle);
    _gumjs_throw (ctx, "expected NativePointer object");
    return FALSE;
  }
}

gboolean
_gumjs_is_instanceof (duk_context * ctx,
                      GumDukHeapPtr object,
                      gchar * class_name)
{
  gboolean result;

  duk_push_heapptr (ctx, object);
  duk_get_global_string (ctx, class_name);
  result = duk_instanceof (ctx, -2, -1);
  duk_pop_2 (ctx);

  return result;
}

gboolean
_gumjs_value_int_try_get (duk_context * ctx,
                          GumDukValue * value,
                          gint * i)
{
  double number;

  if (!_gumjs_value_number_try_get (ctx, value, &number))
    return FALSE;

  *i = (gint) number;

  return TRUE;
}

gboolean
_gumjs_value_uint_try_get (duk_context * ctx,
                          GumDukValue * value,
                          guint * u)
{
  double number;

  if (!_gumjs_value_number_try_get (ctx, value, &number))
    return FALSE;

  if (number < 0)
    goto invalid_uint;

  *u = (guint) number;

  return TRUE;
invalid_uint:
  {
    _gumjs_throw (ctx, "expected a non-negative number");
    return FALSE;
  }
}

gboolean
_gumjs_value_int64_try_get (duk_context * ctx,
                          GumDukValue * value,
                          gint64 * i)
{
  double number;

  if (!_gumjs_value_number_try_get (ctx, value, &number))
    return FALSE;

  *i = (gint64) number;

  return TRUE;
}

gboolean
_gumjs_value_uint64_try_get (duk_context * ctx,
                             GumDukValue * value,
                             guint64 * u)
{
  double number;

  if (!_gumjs_value_number_try_get (ctx, value, &number))
    return FALSE;

  if (number < 0)
    goto invalid_uint;

  *u = (guint64) number;

  return TRUE;
invalid_uint:
  {
    _gumjs_throw (ctx, "expected a non-negative number");
    return FALSE;
  }
}

gboolean
_gumjs_value_number_try_get (duk_context * ctx,
                             GumDukValue * value,
                             gdouble * number)
{
  if (value->type != DUK_TYPE_NUMBER)
    goto invalid_type;

  *number = value->data._number;

  return TRUE;
invalid_type:
  {
    _gumjs_throw (ctx, "expected a number");
    return FALSE;
  }
}

gboolean
_gumjs_value_is_array (duk_context * ctx,
                       GumDukValue * value)
{
  gboolean result = FALSE;
  if (value->type != DUK_TYPE_OBJECT)
    return result;

  duk_push_heapptr (ctx, value->data._heapptr);
  result = duk_is_array (ctx, -1);
  duk_pop (ctx);

  return result;
}

GumDukValue *
_gumjs_get_value (duk_context * ctx,
                  gint idx)
{
  GumDukValue * value;
  if (duk_is_undefined (ctx, idx) || duk_is_null (ctx, idx))
    return NULL;

  value = g_slice_new (GumDukValue);
  value->type = duk_get_type (ctx, idx);
  if (duk_is_string (ctx, idx))
    value->data._string = duk_get_string (ctx, idx);
  else if (duk_is_number (ctx, idx))
    value->data._number = duk_get_number (ctx, idx);
  else if (duk_is_boolean (ctx, idx))
    value->data._boolean = duk_get_boolean (ctx, idx);
  else if (duk_is_object (ctx, idx))
    value->data._heapptr = _gumjs_duk_get_heapptr (ctx, idx);

  return value;
}

void
_gumjs_release_value (duk_context * ctx,
                      GumDukValue * value)
{
  if (value->type == DUK_TYPE_OBJECT)
    _gumjs_duk_release_heapptr (ctx, value->data._heapptr);
  g_free (value);
}

void
_gumjs_push_value (duk_context * ctx,
                   GumDukValue * value)
{
  switch (value->type)
  {
    case DUK_TYPE_BOOLEAN:
      duk_push_boolean (ctx, value->data._boolean);
      break;
    case DUK_TYPE_STRING:
      duk_push_string (ctx, value->data._string);
      break;
    case DUK_TYPE_NUMBER:
      duk_push_number (ctx, value->data._number);
      break;
    case DUK_TYPE_OBJECT:
      duk_push_heapptr (ctx, value->data._heapptr);
      break;
    default:
      g_assert_not_reached ();
  }
}

gboolean
_gumjs_object_try_get_uint (duk_context * ctx,
                            GumDukHeapPtr object,
                            const gchar * key,
                            guint * value)
{
  duk_push_heapptr (ctx, object);
  duk_get_prop_string (ctx, -1, key);

  *value = duk_require_uint (ctx, -1);

  duk_pop_2 (ctx);
  return TRUE;
}

guint
_gumjs_uint_parse (duk_context * ctx,
                   const gchar * str)
{
  gchar * endptr;
  glong value;
  gboolean valid;

  value = strtol (str, &endptr, 10);

  valid = *str != '\0' && *endptr == '\0' && value >= 0;
  if (!valid)
    _gumjs_throw (ctx, "invalid uint");

  return value;
}

void
_gumjs_duk_create_subclass (duk_context * ctx,
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

  if (constructor)
    duk_push_c_function (ctx, constructor, constructor_nargs);
  else
    duk_push_object (ctx);

  duk_dup (ctx, -2);
  if (finalize)
  {
    duk_push_c_function (ctx, finalize, 1);
    duk_set_finalizer (ctx, -2);
  }
  duk_put_prop_string (ctx, -2, "prototype");
  duk_put_prop_string (ctx, -7, name);
  duk_pop_n (ctx, 6);
}

void
_gumjs_duk_add_properties_to_class_by_heapptr (
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
_gumjs_duk_add_properties_to_class (duk_context * ctx,
                                    const gchar * class_name,
                                    const GumDukPropertyEntry * entries)
{
  duk_get_global_string (ctx, class_name);
  duk_get_prop_string (ctx, -1, "prototype");
  _gumjs_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), entries);
  duk_pop_2 (ctx);
}

gboolean
_gumjs_is_arg0_equal_to_prototype (duk_context * ctx,
                                   const gchar * class_name)
{
  gboolean result;

  duk_get_global_string (ctx, class_name);
  duk_get_prop_string (ctx, -1, "prototype");
  result = duk_equals (ctx, 0, -1);
  duk_pop_2 (ctx);

  return result;
}

GumDukHeapPtr
_gumjs_duk_get_this (duk_context * ctx)
{
  GumDukHeapPtr result;

  duk_push_this (ctx);
  result = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}

void
_gumjs_duk_protect (duk_context * ctx,
                    GumDukHeapPtr object)
{
  gchar name[256];
  duk_uint_t ref_count;

  sprintf (name, "\xff" "protected_%p", object);

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
_gumjs_duk_unprotect (duk_context * ctx,
                      GumDukHeapPtr object)
{
  gchar name[256];
  duk_uint_t ref_count;

  sprintf (name, "\xff" "protected_%p", object);

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
_gumjs_duk_get_heapptr (duk_context * ctx,
                        gint idx)
{
  GumDukHeapPtr result;

  result = duk_get_heapptr (ctx, idx);
  _gumjs_duk_protect (ctx, result);

  return result;
}

GumDukHeapPtr
_gumjs_duk_require_heapptr (duk_context * ctx,
                            gint idx)
{
  GumDukHeapPtr result;

  result = duk_require_heapptr (ctx, idx);
  _gumjs_duk_protect (ctx, result);

  return result;
}

void
_gumjs_duk_release_heapptr (duk_context * ctx,
                            GumDukHeapPtr heapptr)
{
  _gumjs_duk_unprotect (ctx, heapptr);
}

GumDukHeapPtr
_gumjs_duk_create_proxy_accessors (duk_context * ctx,
                                   GumDukHeapPtr target,
                                   gpointer getter,
                                   gpointer setter)
{
  gpointer result;

  duk_get_global_string (ctx, "Proxy");
  duk_push_heapptr (ctx, target);
  duk_push_object (ctx);
  if (getter)
  {
    duk_push_c_function (ctx, getter, 3);
    duk_put_prop_string (ctx, -2, "get");
  }
  if (setter)
  {
    duk_push_c_function (ctx, setter, 4);
    duk_put_prop_string (ctx, -2, "set");
  }
  duk_new (ctx, 2);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return result;
}

GumDukWeakRef *
_gumjs_weak_ref_new (duk_context * ctx,
                     GumDukValue * value,
                     GumDukWeakNotify notify,
                     gpointer data,
                     GDestroyNotify data_destroy)
{
  /* TODO: implement */
  return NULL;
}

void
_gumjs_weak_ref_free (GumDukWeakRef * ref)
{
  /* TODO: implement */
}
