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
