/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8value.h"

#if GLIB_SIZEOF_VOID_P == 4
# define GLIB_SIZEOF_VOID_P_IN_NIBBLE 8
#else
# define GLIB_SIZEOF_VOID_P_IN_NIBBLE 16
#endif

#define GUM_MAX_SEND_ARRAY_LENGTH (1024 * 1024)

using namespace v8;

struct GumV8ArgsParseScope
{
  GumV8ArgsParseScope ()
    : committed (false),
      strings (NULL),
      byte_arrays (NULL)
  {
  }

  ~GumV8ArgsParseScope ()
  {
    if (!committed)
    {
      g_slist_foreach (strings, (GFunc) g_free, NULL);
      g_slist_foreach (byte_arrays, (GFunc) g_bytes_unref, NULL);
    }

    g_slist_free (strings);
    g_slist_free (byte_arrays);
  }

  void
  commit ()
  {
    committed = true;
  }

  gchar *
  strdup (const gchar * s)
  {
    gchar * result = g_strdup (s);
    strings = g_slist_prepend (strings, result);
    return result;
  }

  void
  add (GBytes * bytes)
  {
    byte_arrays = g_slist_prepend (byte_arrays, bytes);
  }

  bool committed;
  GSList * strings;
  GSList * byte_arrays;
};

struct GumCpuContextWrapper
{
  GumPersistent<Object>::type * instance;
  GumCpuContext * cpu_context;
};

static void gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info);

static const gchar * gum_exception_type_to_string (GumExceptionType type);

static void gum_cpu_context_on_weak_notify (
    const WeakCallbackInfo<GumCpuContextWrapper> & info);

gboolean
_gum_v8_args_parse (const GumV8Args * args,
                    const gchar * format,
                    ...)
{
  const FunctionCallbackInfo<Value> * info = args->info;
  GumV8Core * core = args->core;
  Isolate * isolate = info->GetIsolate ();
  Local<Context> context = isolate->GetCurrentContext ();
  GumV8ArgsParseScope scope;
  va_list ap;
  int arg_index;
  int arg_count = info->Length ();
  const gchar * t;
  gboolean is_required;

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

    if (arg_index >= arg_count)
    {
      if (is_required)
      {
        _gum_v8_throw_ascii_literal (isolate, "missing argument");
        return FALSE;
      }
      else
      {
        break;
      }
    }

    Local<Value> arg = (*info)[arg_index];

    switch (*t)
    {
      case 'i':
      {
        if (!arg->IsNumber ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an integer");
          return FALSE;
        }

        double value = arg->ToNumber (context).ToLocalChecked ()->Value ();

        *va_arg (ap, gint *) = (gint) value;

        break;
      }
      case 'u':
      {
        if (!arg->IsNumber ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
          return FALSE;
        }

        double value = arg->ToNumber (context).ToLocalChecked ()->Value ();
        if (value < 0)
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
          return FALSE;
        }

        *va_arg (ap, guint *) = (guint) value;

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
          if (!_gum_v8_int64_parse (arg, &i, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_int64_get (arg, &i, core))
            return FALSE;
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
          if (!_gum_v8_uint64_parse (arg, &u, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_uint64_get (arg, &u, core))
            return FALSE;
        }

        *va_arg (ap, guint64 *) = u;

        break;
      }
      case 'z':
      {
        gssize value;

        if (!_gum_v8_ssize_get (arg, &value, core))
          return FALSE;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_v8_size_get (arg, &value, core))
          return FALSE;

        *va_arg (ap, gsize *) = value;

        break;
      }
      case 'n':
      {
        if (!arg->IsNumber ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a number");
          return FALSE;
        }

        *va_arg (ap, gdouble *) =
            arg->ToNumber (context).ToLocalChecked ()->Value ();

        break;
      }
      case 't':
      {
        if (!arg->IsBoolean ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a boolean");
          return FALSE;
        }

        *va_arg (ap, gboolean *) =
            arg->ToBoolean (context).ToLocalChecked ()->Value ();

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
          if (!_gum_v8_native_pointer_parse (arg, &ptr, core))
            return FALSE;
        }
        else
        {
          if (!_gum_v8_native_pointer_get (arg, &ptr, core))
            return FALSE;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 'X':
      {
        if (!arg->IsExternal ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an external pointer");
          return FALSE;
        }

        *va_arg (ap, gpointer *) = arg.As<External> ()->Value ();

        break;
      }
      case 's':
      {
        gchar * str;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          str = NULL;
        }
        else if (arg->IsString ())
        {
          String::Utf8Value arg_utf8 (arg);
          str = scope.strdup (*arg_utf8);
        }
        else
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a string");
          return FALSE;
        }

        *va_arg (ap, gchar **) = str;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_v8_page_protection_get (arg, &prot, core))
          return FALSE;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        *va_arg (ap, Local<Value> *) = arg;

        break;
      }
      case 'O':
      {
        if (!arg->IsObject ())
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an object");
          return FALSE;
        }

        *va_arg (ap, Local<Object> *) = arg.As<Object> ();

        break;
      }
      case 'A':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (arg->IsArray ())
        {
          *va_arg (ap, Local<Array> *) = arg.As<Array> ();
        }
        else if (!(is_nullable && arg->IsNull ()))
        {
          _gum_v8_throw_ascii_literal (isolate, "expected an array");
          return FALSE;
        }

        break;
      }
      case 'F':
      {
        gboolean is_expecting_object, is_nullable;

        is_expecting_object = t[1] == '{';
        if (is_expecting_object)
          t += 2;

        if (is_expecting_object)
        {
          const gchar * next, * end, * t_end;

          if (!arg->IsObject ())
          {
            _gum_v8_throw_ascii_literal (isolate,
                "expected an object containing callbacks");
            return FALSE;
          }
          Local<Object> callbacks = arg.As<Object> ();

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

            Local<Function> * func = va_arg (ap, Local<Function> *);

            if (is_nullable)
            {
              if (!_gum_v8_callbacks_get_opt (callbacks, name, func, core))
                return FALSE;
            }
            else
            {
              if (!_gum_v8_callbacks_get (callbacks, name, func, core))
                return FALSE;
            }

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

          if (arg->IsFunction ())
          {
            *va_arg (ap, Local<Function> *) = arg.As<Function> ();
          }
          else if (!(is_nullable && arg->IsNull ()))
          {
            _gum_v8_throw_ascii_literal (isolate, "expected a function");
            return FALSE;
          }
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

        if (is_nullable && arg->IsNull ())
          bytes = NULL;
        else if ((bytes = _gum_v8_byte_array_get (arg, core)) == NULL)
          return FALSE;

        scope.add (bytes);

        *va_arg (ap, GBytes **) = bytes;

        break;
      }
      case 'C':
      {
        GumCpuContext * cpu_context;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && arg->IsNull ())
        {
          cpu_context = NULL;
        }
        else if (!_gum_v8_cpu_context_get (arg, &cpu_context, core))
        {
          _gum_v8_throw_ascii_literal (isolate, "expected a CpuContext object");
          return FALSE;
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

  scope.commit ();

  return TRUE;
}

Local<String>
_gum_v8_string_new_from_ascii (const gchar * str,
                               Isolate * isolate)
{
  return String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (str));
}

GBytes *
_gum_v8_byte_array_get (Handle<Value> value,
                        GumV8Core * core)
{
  GBytes * result = _gum_v8_byte_array_try_get (value, core);
  if (result == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "unsupported data value");
    return NULL;
  }

  return result;
}

GBytes *
_gum_v8_byte_array_try_get (Handle<Value> value,
                            GumV8Core * core)
{
  if (value->IsArrayBuffer ())
  {
    ArrayBuffer::Contents contents =
        Handle<ArrayBuffer>::Cast (value)->GetContents ();

    return g_bytes_new (contents.Data (), contents.ByteLength ());
  }
  else if (value->IsArray ())
  {
    Handle<Array> array = Handle<Array>::Cast (value);

    gsize data_length = array->Length ();
    if (data_length > GUM_MAX_SEND_ARRAY_LENGTH)
      return NULL;

    Local<Context> context = core->isolate->GetCurrentContext ();

    guint8 * data = (guint8 *) g_malloc (data_length);
    gboolean data_valid = TRUE;

    for (guint i = 0; i != data_length && data_valid; i++)
    {
      gboolean element_valid = FALSE;

      Local<Value> element_value;
      if (array->Get (context, i).ToLocal (&element_value))
      {
        Maybe<uint32_t> element = element_value->Uint32Value (context);
        if (element.IsJust ())
        {
          data[i] = element.FromJust ();
          element_valid = TRUE;
        }
      }

      if (!element_valid)
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

GumV8NativeResource *
_gum_v8_native_resource_new (gpointer data,
                             gsize size,
                             GDestroyNotify notify,
                             GumV8Core * core)
{
  GumV8NativeResource * resource;

  resource = g_slice_new (GumV8NativeResource);
  resource->instance = new GumPersistent<Object>::type (core->isolate,
      _gum_v8_native_pointer_new (data, core));
  resource->instance->MarkIndependent ();
  resource->instance->SetWeak (resource, gum_v8_native_resource_on_weak_notify,
      WeakCallbackType::kParameter);
  resource->data = data;
  resource->size = size;
  resource->notify = notify;
  resource->core = core;

  core->isolate->AdjustAmountOfExternalAllocatedMemory (size);

  g_hash_table_insert (core->native_resources, resource, resource);

  return resource;
}

void
_gum_v8_native_resource_free (GumV8NativeResource * resource)
{
  resource->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -static_cast<gssize> (resource->size));

  delete resource->instance;
  if (resource->notify != NULL)
    resource->notify (resource->data);
  g_slice_free (GumV8NativeResource, resource);
}

static void
gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumV8NativeResource * self = info.GetParameter ();
  g_hash_table_remove (self->core->native_resources, self);
}

gboolean
_gum_v8_size_get (Handle<Value> value,
                  gsize * target,
                  GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    int64_t integer_value = value->IntegerValue ();
    if (integer_value >= 0)
    {
      *target = (gsize) integer_value;
      return TRUE;
    }
  }
  else
  {
    Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (isolate,
        *core->uint64));
    if (uint64->HasInstance (value))
    {
      *target = (gsize) _gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }

    Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
        isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      gint64 int64_value = _gum_v8_int64_get_value (value.As<Object> ());
      if (int64_value >= 0)
      {
        *target = (gsize) int64_value;
        return TRUE;
      }
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
  return FALSE;
}

gboolean
_gum_v8_ssize_get (Handle<Value> value,
                   gssize * target,
                   GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = (gssize) value->IntegerValue ();
    return TRUE;
  }
  else
  {
    Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
        isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      *target = (gssize) _gum_v8_int64_get_value (value.As<Object> ());
      return TRUE;
    }

    Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (isolate,
        *core->uint64));
    if (uint64->HasInstance (value))
    {
      *target = (gssize) _gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "expected an integer");
  return FALSE;
}

Local<Object>
_gum_v8_int64_new (gint64 value,
                   GumV8Core * core)
{
  Local<Object> int64_value (Local<Object>::New (core->isolate,
      *core->int64_value));
  Local<Object> int64_object (int64_value->Clone ());
  _gum_v8_int64_set_value (int64_object, value, core->isolate);
  return int64_object;
}

gboolean
_gum_v8_int64_get (Handle<Value> value,
                   gint64 * target,
                   GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = value->IntegerValue ();
    return TRUE;
  }

  Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
      isolate, *core->int64));
  if (!int64->HasInstance (value))
  {
    _gum_v8_throw_ascii_literal (isolate, "expected an integer");
    return FALSE;
  }

  *target = _gum_v8_int64_get_value (value.As<Object> ());
  return TRUE;
}

gboolean
_gum_v8_int64_parse (Handle<Value> value,
                     gint64 * target,
                     GumV8Core * core)
{
  if (value->IsString ())
  {
    Isolate * isolate = core->isolate;

    String::Utf8Value value_as_utf8 (value);
    const gchar * value_as_string = *value_as_utf8;
    gchar * end;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *target = g_ascii_strtoll (value_as_string + 2, &end, 16);
      if (end == value_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *target = g_ascii_strtoll (value_as_string, &end, 10);
      if (end == value_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }

    return TRUE;
  }

  return _gum_v8_int64_get (value, target, core);
}

Local<Object>
_gum_v8_uint64_new (guint64 value,
                    GumV8Core * core)
{
  Local<Object> uint64_value (Local<Object>::New (core->isolate,
      *core->uint64_value));
  Local<Object> uint64_object (uint64_value->Clone ());
  _gum_v8_uint64_set_value (uint64_object, value, core->isolate);
  return uint64_object;
}

gint64
_gum_v8_int64_get_value (Handle<Object> object)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gpointer p;
    gint64 i;
  } v;

  v.p = object->GetInternalField (0).As<External> ()->Value ();

  return v.i;
#else
  union
  {
    gpointer p;
    guint32 bits;
  } upper, lower;
  union
  {
    guint64 bits;
    gint64 i;
  } v;

  upper.p = object->GetInternalField (0).As<External> ()->Value ();
  lower.p = object->GetInternalField (1).As<External> ()->Value ();

  v.bits = static_cast<guint64> (upper.bits) << 32 |
      static_cast<guint64> (lower.bits);

  return v.i;
#endif
}

void
_gum_v8_int64_set_value (Handle<Object> object,
                         gint64 value,
                         Isolate * isolate)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gint64 i;
    gpointer p;
  } v;

  v.i = value;

  object->SetInternalField (0, External::New (isolate, v.p));
#else
  union
  {
    gint64 i;
    guint64 bits;
  } v;
  union
  {
    guint32 bits;
    gpointer p;
  } upper, lower;

  v.i = value;

  upper.bits = v.bits >> 32;
  lower.bits = v.bits & 0xffffffff;

  object->SetInternalField (0, External::New (isolate, upper.p));
  object->SetInternalField (1, External::New (isolate, lower.p));
#endif
}

gboolean
_gum_v8_uint64_get (Handle<Value> value,
                    guint64 * target,
                    GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = value->IntegerValue ();
    return TRUE;
  }

  Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (
      isolate, *core->uint64));
  if (!uint64->HasInstance (value))
  {
    _gum_v8_throw_ascii_literal (isolate, "expected an unsigned integer");
    return FALSE;
  }

  *target = _gum_v8_uint64_get_value (value.As<Object> ());
  return TRUE;
}

gboolean
_gum_v8_uint64_parse (Handle<Value> value,
                      guint64 * target,
                      GumV8Core * core)
{
  if (value->IsString ())
  {
    Isolate * isolate = core->isolate;

    String::Utf8Value value_as_utf8 (value);
    const gchar * value_as_string = *value_as_utf8;
    gchar * end;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *target = g_ascii_strtoull (value_as_string + 2, &end, 16);
      if (end == value_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *target = g_ascii_strtoull (value_as_string, &end, 10);
      if (end == value_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }

    return TRUE;
  }

  return _gum_v8_uint64_get (value, target, core);
}

guint64
_gum_v8_uint64_get_value (Handle<Object> object)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gpointer p;
    guint64 u;
  } v;

  v.p = object->GetInternalField (0).As<External> ()->Value ();

  return v.u;
#else
  union
  {
    gpointer p;
    guint32 bits;
  } upper, lower;

  upper.p = object->GetInternalField (0).As<External> ()->Value ();
  lower.p = object->GetInternalField (1).As<External> ()->Value ();

  return static_cast<guint64> (upper.bits) << 32 |
      static_cast<guint64> (lower.bits);
#endif
}

void
_gum_v8_uint64_set_value (Handle<Object> object,
                          guint64 value,
                          Isolate * isolate)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    guint64 u;
    gpointer p;
  } v;

  v.u = value;

  object->SetInternalField (0, External::New (isolate, v.p));
#else
  union
  {
    guint32 bits;
    gpointer p;
  } upper, lower;

  upper.bits = value >> 32;
  lower.bits = value & 0xffffffff;

  object->SetInternalField (0, External::New (isolate, upper.p));
  object->SetInternalField (1, External::New (isolate, lower.p));
#endif
}

Local<Object>
_gum_v8_native_pointer_new (gpointer address,
                            GumV8Core * core)
{
  Local<Object> native_pointer_value (Local<Object>::New (core->isolate,
      *core->native_pointer_value));
  Local<Object> native_pointer_object (native_pointer_value->Clone ());
  native_pointer_object->SetInternalField (0,
      External::New (core->isolate, address));
  return native_pointer_object;
}

gboolean
_gum_v8_native_pointer_get (Handle<Value> value,
                            gpointer * target,
                            GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  gboolean success = FALSE;

  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (
      isolate, *core->native_pointer));
  if (native_pointer->HasInstance (value))
  {
    *target = GUMJS_NATIVE_POINTER_VALUE (value.As<Object> ());
    success = TRUE;
  }
  else
  {
    /* Cannot use isObject() here as that returns false for proxies */
    MaybeLocal<Object> maybe_obj;
    {
      TryCatch trycatch (isolate);
      maybe_obj = value->ToObject (isolate);
      trycatch.Reset ();
    }

    Local<Object> obj;
    if (maybe_obj.ToLocal (&obj))
    {
      Local<Context> context = isolate->GetCurrentContext ();
      Local<String> handle_key (Local<String>::New (isolate,
          *core->handle_key));
      if (obj->Has (context, handle_key).FromJust ())
      {
        Local<Value> handle = obj->Get (context, handle_key).ToLocalChecked ();
        if (native_pointer->HasInstance (handle))
        {
          *target = GUMJS_NATIVE_POINTER_VALUE (handle.As<Object> ());
          success = TRUE;
        }
      }
    }
  }

  if (!success)
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a NativePointer object");
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_v8_native_pointer_parse (Handle<Value> value,
                              gpointer * target,
                              GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsString ())
  {
    String::Utf8Value ptr_as_utf8 (value);
    const gchar * ptr_as_string = *ptr_as_utf8;
    gchar * endptr;
    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      *target = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string + 2, &endptr, 16));
      if (endptr == ptr_as_string + 2)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid hexadecimal string");
        return FALSE;
      }
    }
    else
    {
      *target = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string, &endptr, 10));
      if (endptr == ptr_as_string)
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid decimal string");
        return FALSE;
      }
    }

    return TRUE;
  }
  else if (value->IsNumber ())
  {
    *target = GSIZE_TO_POINTER (value.As<Number> ()->Value ());
    return TRUE;
  }

  return _gum_v8_native_pointer_get (value, target, core);
}

void
_gum_v8_throw (Isolate * isolate,
               const gchar * format,
               ...)
{
  va_list ap;
  gchar * message;

  va_start (ap, format);
  message = g_strdup_vprintf (format, ap);

  _gum_v8_throw_literal (isolate, message);

  g_free (message);
  va_end (ap);
}

void
_gum_v8_throw_literal (Isolate * isolate,
                       const gchar * message)
{
  isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
      message)));
}

void
_gum_v8_throw_ascii (Isolate * isolate,
                     const gchar * format,
                     ...)
{
  va_list ap;
  gchar * message;

  va_start (ap, format);
  message = g_strdup_vprintf (format, ap);

  _gum_v8_throw_ascii_literal (isolate, message);

  g_free (message);
  va_end (ap);
}

void
_gum_v8_throw_ascii_literal (Isolate * isolate,
                             const gchar * message)
{
  isolate->ThrowException (Exception::Error (
      _gum_v8_string_new_from_ascii (message, isolate)));
}

void
_gum_v8_throw_native (GumExceptionDetails * details,
                      GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);
  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, context),
      core);
  isolate->ThrowException (ex);
}

void
_gum_v8_parse_exception_details (GumExceptionDetails * details,
                                 Local<Object> & exception,
                                 Local<Object> & cpu_context,
                                 GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  gchar * message = gum_exception_details_to_string (details);
  Local<Object> ex =
      Exception::Error (String::NewFromUtf8 (isolate, message)).As<Object> ();
  g_free (message);

  _gum_v8_object_set_ascii (ex, "type",
      gum_exception_type_to_string (details->type), core);
  _gum_v8_object_set_pointer (ex, "address", details->address, core);

  const GumExceptionMemoryDetails * md = &details->memory;
  if (md->operation != GUM_MEMOP_INVALID)
  {
    Local<Object> memory (Object::New (isolate));
    _gum_v8_object_set_ascii (memory, "operation",
        _gum_v8_memory_operation_to_string (md->operation), core);
    _gum_v8_object_set_pointer (memory, "address", md->address, core);
    _gum_v8_object_set (ex, "memory", memory, core);
  }

  Local<Object> context = _gum_v8_cpu_context_new (&details->context, core);
  _gum_v8_object_set (ex, "context", context, core);
  _gum_v8_object_set_pointer (ex, "nativeContext", details->native_context, core);

  exception = ex;
  cpu_context = context;
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

v8::Local<v8::Object>
_gum_v8_cpu_context_new (const GumCpuContext * cpu_context,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Local<Object> cpu_context_value (Local<Object>::New (isolate,
      *core->cpu_context_value));
  Local<Object> cpu_context_object (cpu_context_value->Clone ());
  cpu_context_object->SetInternalField (0,
      External::New (isolate, const_cast<GumCpuContext *> (cpu_context)));
  const bool is_mutable = false;
  cpu_context_object->SetInternalField (1, Boolean::New (isolate, is_mutable));
  return cpu_context_object;
}

v8::Local<v8::Object>
_gum_v8_cpu_context_new (GumCpuContext * cpu_context,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Local<Object> cpu_context_value (Local<Object>::New (isolate,
      *core->cpu_context_value));
  Local<Object> cpu_context_object (cpu_context_value->Clone ());
  cpu_context_object->SetInternalField (0,
      External::New (isolate, cpu_context));
  const bool is_mutable = true;
  cpu_context_object->SetInternalField (1, Boolean::New (isolate, is_mutable));
  return cpu_context_object;
}

void
_gum_v8_cpu_context_free_later (GumPersistent<Object>::type * cpu_context,
                                GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  GumCpuContextWrapper * wrapper;

  Local<Object> instance (Local<Object>::New (isolate, *cpu_context));
  GumCpuContext * original = static_cast<GumCpuContext *> (
      instance->GetInternalField (0).As<External> ()->Value ());
  GumCpuContext * copy = g_slice_dup (GumCpuContext, original);
  instance->SetInternalField (0, External::New (isolate, copy));
  const bool is_mutable = false;
  instance->SetInternalField (1, Boolean::New (isolate, is_mutable));

  wrapper = g_slice_new (GumCpuContextWrapper);
  wrapper->instance = cpu_context;
  wrapper->cpu_context = copy;

  cpu_context->SetWeak (wrapper, gum_cpu_context_on_weak_notify,
      WeakCallbackType::kParameter);
  cpu_context->MarkIndependent ();
}

static void
gum_cpu_context_on_weak_notify (
    const WeakCallbackInfo<GumCpuContextWrapper> & info)
{
  GumCpuContextWrapper * wrapper = info.GetParameter ();

  delete wrapper->instance;

  g_slice_free (GumCpuContext, wrapper->cpu_context);

  g_slice_free (GumCpuContextWrapper, wrapper);
}

gboolean
_gum_v8_cpu_context_get (v8::Handle<v8::Value> value,
                         GumCpuContext ** target,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<FunctionTemplate> cpu_context (Local<FunctionTemplate>::New (
      isolate, *core->cpu_context));
  if (!cpu_context->HasInstance (value))
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a CpuContext object");
    return FALSE;
  }
  *target = GUMJS_CPU_CONTEXT_VALUE (value.As<Object> ());

  return TRUE;
}

const gchar *
_gum_v8_thread_state_to_string (GumThreadState state)
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
_gum_v8_memory_operation_to_string (GumMemoryOperation operation)
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
_gum_v8_object_set (Handle<Object> object,
                    const gchar * key,
                    Handle<Value> value,
                    GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Maybe<bool> success = object->Set (isolate->GetCurrentContext (),
      _gum_v8_string_new_from_ascii (key, isolate), value);
  return success.IsJust ();
}

gboolean
_gum_v8_object_set_uint (Handle<Object> object,
                         const gchar * key,
                         guint value,
                         GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      Integer::NewFromUnsigned (core->isolate, value),
      core);
}

gboolean
_gum_v8_object_set_pointer (Handle<Object> object,
                            const gchar * key,
                            gpointer value,
                            GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      _gum_v8_native_pointer_new (value, core),
      core);
}

gboolean
_gum_v8_object_set_pointer (Handle<Object> object,
                            const gchar * key,
                            GumAddress value,
                            GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (value), core),
      core);
}

gboolean
_gum_v8_object_set_ascii (Handle<Object> object,
                          const gchar * key,
                          const gchar * value,
                          GumV8Core * core)
{
  return _gum_v8_object_set (object, key,
      _gum_v8_string_new_from_ascii (value, core->isolate), core);
}

gboolean
_gum_v8_object_set_utf8 (Handle<Object> object,
                         const gchar * key,
                         const gchar * value,
                         GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      String::NewFromUtf8 (core->isolate, value),
      core);
}

gboolean
_gum_v8_callbacks_get (Handle<Object> callbacks,
                       const gchar * name,
                       Handle<Function> * callback_function,
                       GumV8Core * core)
{
  if (!_gum_v8_callbacks_get_opt (callbacks, name, callback_function, core))
    return FALSE;

  if ((*callback_function).IsEmpty ())
  {
    _gum_v8_throw_ascii (core->isolate, "%s callback is required", name);
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_v8_callbacks_get_opt (Handle<Object> callbacks,
                           const gchar * name,
                           Handle<Function> * callback_function,
                           GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<Value> value =
      callbacks->Get (_gum_v8_string_new_from_ascii (name, isolate));
  if (value->IsUndefined () || value->IsNull ())
    return TRUE;

  if (!value->IsFunction ())
  {
    _gum_v8_throw_ascii (isolate, "%s must be a function", name);
    return FALSE;
  }

  *callback_function = value.As<Function> ();
  return TRUE;
}

gboolean
_gum_v8_page_protection_get (Handle<Value> prot_val,
                             GumPageProtection * prot,
                             GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (!prot_val->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "expected a string specifying memory protection");
    return FALSE;
  }
  String::Utf8Value prot_str (prot_val);

  *prot = GUM_PAGE_NO_ACCESS;
  for (const gchar * ch = *prot_str; *ch != '\0'; ch++)
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
        _gum_v8_throw_ascii_literal (isolate, "invalid character in memory "
            "protection specifier string");
        return FALSE;
    }
  }

  return TRUE;
}

Local<ObjectTemplate>
_gum_v8_create_module (const gchar * name,
                       Handle<ObjectTemplate> scope,
                       Isolate * isolate)
{
  auto module = ObjectTemplate::New (isolate);
  scope->Set (_gum_v8_string_new_from_ascii (name, isolate), module);
  return module;
}

void
_gum_v8_module_add (v8::Handle<v8::External> module,
                    v8::Handle<v8::ObjectTemplate> object,
                    const GumV8Function * functions,
                    v8::Isolate * isolate)
{
  auto func = functions;
  while (func->name != NULL)
  {
    object->Set (_gum_v8_string_new_from_ascii (func->name, isolate),
        FunctionTemplate::New (isolate, func->callback, module));
    func++;
  }
}

Local<FunctionTemplate>
_gum_v8_create_class (const gchar * name,
                      FunctionCallback ctor,
                      Handle<ObjectTemplate> scope,
                      Handle<External> module,
                      Isolate * isolate)
{
  auto klass = FunctionTemplate::New (isolate, ctor, module);
  klass->SetClassName (_gum_v8_string_new_from_ascii (name, isolate));
  klass->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (_gum_v8_string_new_from_ascii (name, isolate), klass);
  return klass;
}

void
_gum_v8_class_add (Handle<FunctionTemplate> klass,
                   const GumV8Function * functions,
                   Isolate * isolate)
{
  auto proto = klass->PrototypeTemplate ();

  auto func = functions;
  while (func->name != NULL)
  {
    proto->Set (_gum_v8_string_new_from_ascii (func->name, isolate),
        FunctionTemplate::New (isolate, func->callback));
    func++;
  }
}
