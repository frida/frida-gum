/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukvalue.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

static void gum_native_resource_on_weak_notify (
    GumDukNativeResource * resource);

static const gchar * gum_exception_type_to_string (GumExceptionType type);

gboolean
_gumjs_args_parse (duk_context * ctx,
                   const gchar * format,
                   ...)
{
  va_list ap;
  guint arg_index;
  const gchar * t;
  gboolean is_required;
  GSList * byte_arrays = NULL;

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

    if (arg_index > duk_get_top (ctx))
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
        if (!duk_is_undefined (ctx, arg_index))
            *va_arg (ap, gint *) = duk_get_int (ctx, arg_index);

        break;
      }
      case 'u':
      {
        if (!duk_is_undefined (ctx, arg_index))
            *va_arg (ap, guint *) = duk_get_uint (ctx, arg_index);

        break;
      }
      case 'n':
      {
        if (!duk_is_undefined (ctx, arg_index))
            *va_arg (ap, gdouble *) = duk_get_number (ctx, arg_index);

        break;
      }
      case 'p':
      {
        gboolean is_fuzzy;
        gpointer ptr = NULL;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (duk_is_object (ctx, arg_index) &&
              _gumjs_is_instanceof (ctx, duk_require_heapptr (ctx, arg_index),
              "NativePointer"))
          {
            ptr = _gumjs_native_pointer_value (ctx,
                duk_require_heapptr (ctx, arg_index));
          }
          else if (duk_is_object (ctx, arg_index))
          {
            duk_get_prop_string (ctx, arg_index, "handle");
            // [ ... handle ]
            if (_gumjs_is_instanceof (ctx, duk_require_heapptr (ctx, -1),
                "NativePointer"))
            {
              ptr = _gumjs_native_pointer_value (ctx,
                  duk_require_heapptr (ctx, -1));
            }
            duk_pop (ctx);
            // [ ... ]
          }
          else if (duk_is_string (ctx, arg_index))
          {
            gchar * ptr_as_string, * endptr;
            gboolean valid;

            ptr_as_string = (gchar *) duk_require_string (ctx, arg_index);

            if (g_str_has_prefix (ptr_as_string, "0x"))
            {
              ptr = GSIZE_TO_POINTER (
                  g_ascii_strtoull (ptr_as_string + 2, &endptr, 16));
              valid = endptr != ptr_as_string + 2;
              if (!valid)
              {
                _gumjs_throw (ctx,
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
                _gumjs_throw (ctx,
                    "argument is not a valid decimal string");
              }
            }

            if (!valid)
              goto error;
          }
          else if (duk_is_number (ctx, arg_index))
          {
            gulong i;

            i = duk_require_number (ctx, arg_index);

            ptr = (gpointer) i ;
          }
          else
          {
            _gumjs_throw (ctx, "invalid pointer value");
            goto error;
          }
        }
        else
        {
          if (_gumjs_is_instanceof (ctx, duk_require_heapptr (ctx, arg_index),
              "NativePointer"))
          {
            ptr = _gumjs_native_pointer_value (ctx,
                duk_require_heapptr (ctx, arg_index));
          }
          else if (duk_is_object (ctx, arg_index))
          {
            duk_get_prop_string (ctx, arg_index, "handle");
            // [ ... handle ]
            if (_gumjs_is_instanceof (ctx, duk_require_heapptr (ctx, -1),
                "NativePointer"))
            {
              ptr = _gumjs_native_pointer_value (ctx,
                  duk_require_heapptr (ctx, -1));
            }
            duk_pop (ctx);
            // [ ... ]
          }
          else
            goto error;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;
        const gchar * prot_str, * ch;
        gboolean valid;

        prot_str = duk_require_string (ctx, arg_index);

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
              _gumjs_throw (ctx,
                  "invalid character in memory protection specifier string");
              valid = FALSE;
              break;
          }
        }

        if (valid)
          *va_arg (ap, GumPageProtection *) = prot;
        else
          goto error;

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
          if (duk_is_undefined (ctx, arg_index) || duk_is_null (ctx, arg_index))
            str = NULL;
          else
            str = duk_require_string (ctx, arg_index);
        }
        else
        {
          str = duk_require_string (ctx, arg_index);
        }

        *va_arg (ap, const gchar **) = str;

        break;
      }
      case 'V':
      {

        *va_arg (ap, GumDukValue **) = _gumjs_get_value (ctx, arg_index);

        break;
      }
      case 'O':
      {
        if (!duk_is_object (ctx, arg_index))
        {
          _gumjs_throw (ctx, "expected an object");
          goto error;
        }

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
        {
          array = duk_require_heapptr (ctx, arg_index);
        }
        else if (is_nullable &&
            (duk_is_undefined (ctx, arg_index) || duk_is_null (ctx, arg_index)))
        {
          array = NULL;
        }
        else
        {
          _gumjs_throw (ctx, "expected an array");
          goto error;
        }

        *va_arg (ap, GumDukHeapPtr *) = array;

        break;
      }
      case 'F':
      {
        GumDukHeapPtr func = NULL;
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
              duk_get_prop_string (ctx, arg_index, name);
              if (duk_is_undefined (ctx, -1) || duk_is_null (ctx, -1))
                func = NULL;
              else if (duk_is_function (ctx, -1))
                func = duk_get_heapptr (ctx, -1);
              duk_pop (ctx);
            }
            else
            {
              duk_get_prop_string (ctx, arg_index, name);
              if (duk_is_function (ctx, -1))
                func = duk_get_heapptr (ctx, -1);
              else
                goto error;
              duk_pop (ctx);
            }

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

          if (is_nullable)
          {
            if (duk_is_undefined (ctx, arg_index) ||
                duk_is_null (ctx, arg_index))
            {
              func = NULL;
            }
            else if (duk_is_function (ctx, arg_index))
            {
              func = duk_require_heapptr (ctx, arg_index);
            }
          }
          else
          {
            func = duk_require_heapptr (ctx, arg_index);
          }

          *va_arg (ap, GumDukHeapPtr *) = func;
        }

        break;
      }
      case 'B':
      {
        GBytes * bytes;
        gboolean is_nullable;
        guint data_length, i;
        guint8 * data;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (duk_is_undefined (ctx, arg_index) || duk_is_null (ctx, arg_index))
        {
          if (is_nullable)
            bytes = NULL;
          else
            goto error;
        }
        else
        {
          if (!duk_is_object (ctx, arg_index))
            goto error;

          duk_get_prop_string (ctx, arg_index, "length");
          data_length = duk_get_uint (ctx, -1);
          duk_pop (ctx);

          data = g_malloc (data_length);
          for(i = 0; i < data_length; i++)
          {
            duk_get_prop_index (ctx, arg_index, i);
            data[i] = (guint8) duk_require_uint (ctx, -1);
            duk_pop (ctx);
          }

          bytes = g_bytes_new_take (data, data_length);
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

        if (duk_is_undefined (ctx, arg_index) || duk_is_null (ctx, arg_index))
        {
          if (is_nullable)
            cpu_context = NULL;
          else
            goto error;
        }
        else if (_gumjs_is_instanceof(ctx, duk_get_heapptr (ctx, arg_index),
            "CpuContext"))
        {
          GumDukCpuContext * instance;

          instance = _gumjs_get_private_data (ctx,
              duk_require_heapptr (ctx, arg_index));
          cpu_context = instance->handle;
        }
        else
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
    _gumjs_throw (ctx, "missing argument");
    goto error;
  }
error:
  {
    va_end (ap);

    g_slist_foreach (byte_arrays, (GFunc) g_bytes_unref, NULL);
    g_slist_free (byte_arrays);

    return FALSE;
  }
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
_gumjs_native_pointer_new_priv (duk_context * ctx,
                                GumDukHeapPtr object,
                                gpointer address,
                                GumDukCore * core)
{
  GumDukNativePointer * ptr;

  ptr = g_slice_new (GumDukNativePointer);
  ptr->instance_size = sizeof (GumDukNativePointer);
  ptr->value = address;

  _gumjs_set_private_data (ctx, object, ptr);

  return object;
}

GumDukHeapPtr
_gumjs_native_pointer_new (duk_context * ctx,
                           gpointer address,
                           GumDukCore * core)
{
  GumDukHeapPtr result;

  duk_get_global_string (ctx, "NativePointer");
  // [ NativePointer ]
  duk_push_number (ctx, GPOINTER_TO_SIZE(address));
  // [ NativePointer address ]
  duk_new (ctx, 1);
  // [ nativepointerinst ]
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  return result;
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
  // [ CpuContext ]
  res = duk_pnew (ctx, 0);
  if (res)
    printf ("error during pnew");
  // [ cpucontextinst ]
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  _gumjs_set_private_data (ctx, result, scc);

  return result;
}

gpointer
_gumjs_get_private_data (duk_context * ctx,
                         GumDukHeapPtr object)
{
  gpointer result;

  duk_push_heapptr (ctx, object);
  // [ object ]
  duk_get_prop_string (ctx, -1, "\xff" "privatedata");
  // [ object privatedata ]
  if (duk_is_undefined (ctx, -1))
    result = NULL;
  else
    result = duk_require_pointer (ctx, -1);
  duk_pop_2 (ctx);
  // []

  return result;
}

gboolean
_gumjs_is_instanceof (duk_context * ctx,
                      GumDukHeapPtr object,
                      gchar * classname)
{
  gboolean result;
  duk_push_heapptr (ctx, object);
  // [ object ]
  duk_get_global_string (ctx, classname);
  // [ object class ]
  result = duk_instanceof (ctx, -2, -1);
  duk_pop_2 (ctx);
  // []
  return result;
}

void
_gumjs_set_private_data (duk_context * ctx,
                         GumDukHeapPtr object,
                         gpointer privatedata)
{
  duk_push_heapptr (ctx, object);
  // [ object ]
  duk_push_pointer (ctx, privatedata);
  // [ object privatedata ]
  duk_put_prop_string (ctx, -2, "\xff" "privatedata");
  // [ object ]
  duk_pop (ctx);
  // []
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
  // [ ArrayBuffer ]
  duk_push_int (ctx, size);
  // [ ArrayBuffer size ]
  duk_new (ctx, 1);
  // [ instance ]
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

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
  va_list args;

  va_start (args, format);
  duk_push_error_object_va (ctx, DUK_ERR_ERROR, format, args);
  va_end (args);

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
  // [ errorinst ]
  g_free (message);
  ex = _gumjs_duk_get_heapptr (ctx, -1);

  duk_push_string (ctx, gum_exception_type_to_string (details->type));
  // [ errorinst type ]
  duk_put_prop_string (ctx, -2, "type");
  // [ errorinst ]
  duk_push_pointer (ctx, details->address);
  // [ errorinst address ]
  duk_put_prop_string (ctx, -2, "address");
  // [ errorinst ]

  if (md->operation != GUM_MEMOP_INVALID)
  {
    duk_push_object (ctx);
    // [ errorinst newobject ]
    duk_push_string (ctx, _gumjs_memory_operation_to_string (md->operation));
    // [ errorinst newobject operation ]
    duk_put_prop_string (ctx, -2, "operation");
    // [ errorinst newobject ]
    duk_push_pointer (ctx, md->address);
    // [ errorinst newobject address ]
    duk_put_prop_string (ctx, -2, "address");
    // [ errorinst newobject ]
    duk_put_prop_string (ctx, -2, "memory");
    // [ errorinst ]
  }

  cc = _gumjs_cpu_context_new (ctx, &details->context,
      GUM_CPU_CONTEXT_READWRITE, core);
  duk_push_heapptr (ctx, cc);
  // [ errorinst cpucontext ]
  duk_put_prop_string (ctx, -2, "context");
  // [ errorinst ]
  duk_push_pointer (ctx, details->native_context);
  // [ errorinst nativeContext ]
  duk_put_prop_string (ctx, -2, "nativeContext");
  // [ errorinst ]

  duk_pop (ctx);
  // []
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
      // [ value ]
      duk_get_prop_string (ctx, -1, "length");
      // [ value length ]
      buffer_size = duk_get_uint (ctx, -1);
      duk_pop (ctx);
      // [ value ]
      data = g_malloc (buffer_size);
      for (i = 0; i < buffer_size; i++)
      {
        duk_get_prop_index (ctx, -1, i);
        data[i] = (guint8) duk_require_uint (ctx, -1);
        duk_pop (ctx);
      }
      duk_pop (ctx);
      // []
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
                                 const gchar * classname)
{
  gboolean result = FALSE;
  if (value->type != DUK_TYPE_OBJECT)
    return result;

  duk_push_heapptr (ctx, value->data._heapptr);
  // [ object ]
  duk_get_global_string (ctx, classname);
  // [ object class ]
  result = duk_instanceof (ctx, -2, -1);
  duk_pop_2 (ctx);
  // []
  return result;
}

gboolean
_gumjs_object_try_get (duk_context * ctx,
                       GumDukHeapPtr object,
                       const gchar * key,
                       GumDukValue ** value)
{
  duk_push_heapptr (ctx, object);
  // [ object ]
  duk_get_prop_string (ctx, -1, key);
  // [ object value ]
  *value = _gumjs_get_value (ctx, -1);
  duk_pop_2 (ctx);
  // []
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
    value->data._heapptr = duk_get_heapptr (ctx, idx);

  return value;
}

gboolean
_gumjs_object_try_get_uint (duk_context * ctx,
                            GumDukHeapPtr object,
                            const gchar * key,
                            guint * value)
{
  duk_push_heapptr (ctx, object);
  // [ object ]
  duk_get_prop_string (ctx, -1, key);
  // [ object value ]

  *value = duk_require_uint (ctx, -1);

  duk_pop_2 (ctx);
  // []
  return TRUE;
}

gboolean
_gumjs_uint_try_parse (duk_context * ctx,
                       const gchar * str,
                       guint * u)
{
  gchar * endptr;
  glong value;
  gboolean valid;

  value = strtol (str, &endptr, 10);
  valid = *str != '\0' && *endptr == '\0' && value >= 0;

  if (valid)
    *u = value;
  else
    _gumjs_throw (ctx, "invalid uint");

  return valid;
}
