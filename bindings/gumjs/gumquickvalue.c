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
  _gum_quick_throw_literal (args->ctx, "not yet implemented");
  return FALSE;
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
    goto expected_number;

  if (JS_ToInt32 (ctx, &v, val) != 0)
    return FALSE;

  *i = v;
  return TRUE;

expected_number:
  {
    _gum_quick_throw_literal (ctx, "expected a number");
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
    goto expected_number;

  if (JS_ToUint32 (ctx, &v, val) != 0)
    return FALSE;

  *u = v;
  return TRUE;

expected_number:
  {
    _gum_quick_throw_literal (ctx, "expected a number");
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
