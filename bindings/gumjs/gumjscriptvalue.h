/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_VALUE_H__
#define __GUM_JSCRIPT_VALUE_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

#define GUM_NATIVE_POINTER_VALUE(o) \
  JSObjectGetPrivate ((JSObjectRef) (o))

typedef struct _GumScriptArgs GumScriptArgs;

struct _GumScriptArgs
{
  gsize count;
  const JSValueRef * values;
  JSValueRef * exception;

  JSContextRef ctx;
  GumScriptCore * core;
};

G_GNUC_INTERNAL gboolean _gumjs_args_parse (const GumScriptArgs * self,
    const gchar * format, ...);

G_GNUC_INTERNAL GumScriptWeakRef * _gumjs_weak_ref_new (JSContextRef ctx,
    JSValueRef value, GumScriptWeakNotify notify, gpointer data,
    GDestroyNotify data_destroy);
G_GNUC_INTERNAL JSValueRef _gumjs_weak_ref_get (GumScriptWeakRef * ref);
G_GNUC_INTERNAL void _gumjs_weak_ref_free (GumScriptWeakRef * ref);

G_GNUC_INTERNAL gboolean _gumjs_int_try_get (JSContextRef ctx,
    JSValueRef value, gint * i, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_uint_try_get (JSContextRef ctx,
    JSValueRef value, guint * i, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_number_try_get (JSContextRef ctx,
    JSValueRef value, gdouble * number, JSValueRef * exception);

G_GNUC_INTERNAL gchar * _gumjs_string_get (JSContextRef ctx,
    JSValueRef value);
G_GNUC_INTERNAL gboolean _gumjs_string_try_get (JSContextRef ctx,
    JSValueRef value, gchar ** str, JSValueRef * exception);
G_GNUC_INTERNAL gchar * _gumjs_string_from_jsc (JSStringRef str);
G_GNUC_INTERNAL gchar * _gumjs_string_from_value (JSContextRef ctx,
    JSValueRef value);
G_GNUC_INTERNAL JSValueRef _gumjs_string_to_value (JSContextRef ctx,
    const gchar * str);

G_GNUC_INTERNAL JSValueRef _gumjs_object_get (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL gboolean _gumjs_object_try_get (JSContextRef ctx,
    JSObjectRef object, const gchar * key, JSValueRef * value,
    JSValueRef * exception);
G_GNUC_INTERNAL guint _gumjs_object_get_uint (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL gboolean _gumjs_object_try_get_uint (JSContextRef ctx,
    JSObjectRef object, const gchar * key, guint * value,
    JSValueRef * exception);
G_GNUC_INTERNAL gchar * _gumjs_object_get_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL gboolean _gumjs_object_try_get_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key, gchar ** value,
    JSValueRef * exception);
G_GNUC_INTERNAL void _gumjs_object_set (JSContextRef ctx, JSObjectRef object,
    const gchar * key, JSValueRef value);
G_GNUC_INTERNAL gboolean _gumjs_object_try_set (JSContextRef ctx,
    JSObjectRef object, const gchar * key, JSValueRef value,
    JSValueRef * exception);
G_GNUC_INTERNAL void _gumjs_object_set_int (JSContextRef ctx,
    JSObjectRef object, const gchar * key, gint value);
G_GNUC_INTERNAL gboolean _gumjs_object_try_set_int (JSContextRef ctx,
    JSObjectRef object, const gchar * key, gint value, JSValueRef * exception);
G_GNUC_INTERNAL void _gumjs_object_set_uint (JSContextRef ctx,
    JSObjectRef object, const gchar * key, guint value);
G_GNUC_INTERNAL gboolean _gumjs_object_try_set_uint (JSContextRef ctx,
    JSObjectRef object, const gchar * key, guint value, JSValueRef * exception);
G_GNUC_INTERNAL void _gumjs_object_set_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key, const gchar * value);
G_GNUC_INTERNAL gboolean _gumjs_object_try_set_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key, const gchar * value,
    JSValueRef * exception);
G_GNUC_INTERNAL void _gumjs_object_set_function (JSContextRef ctx,
    JSObjectRef object, const gchar * key,
    JSObjectCallAsFunctionCallback callback);
G_GNUC_INTERNAL gboolean _gumjs_object_try_set_function (JSContextRef ctx,
    JSObjectRef object, const gchar * key,
    JSObjectCallAsFunctionCallback callback, JSValueRef * exception);

G_GNUC_INTERNAL gboolean _gumjs_callbacks_try_get (JSContextRef ctx,
    JSValueRef callbacks, const gchar * name, JSObjectRef * callback,
    JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_callbacks_try_get_opt (JSContextRef ctx,
    JSValueRef callbacks, const gchar * name, JSObjectRef * callback,
    JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_callback_try_get (JSContextRef ctx,
    JSValueRef value, JSObjectRef * callback, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_callback_try_get_opt (JSContextRef ctx,
    JSValueRef value, JSObjectRef * callback, JSValueRef * exception);

G_GNUC_INTERNAL JSObjectRef _gumjs_native_pointer_new (JSContextRef ctx,
    gpointer address, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gumjs_native_pointer_try_get (JSContextRef ctx,
    JSValueRef value, GumScriptCore * core, gpointer * target,
    JSValueRef * exception);

G_GNUC_INTERNAL GumNativeResource * _gumjs_native_resource_new (
    JSContextRef ctx, gpointer data, GDestroyNotify notify,
    GumScriptCore * core, JSObjectRef * handle);
G_GNUC_INTERNAL void _gumjs_native_resource_free (GumNativeResource * resource);

G_GNUC_INTERNAL JSObjectRef _gumjs_array_buffer_new (JSContextRef ctx,
    gsize size, GumScriptCore * core);
G_GNUC_INTERNAL gpointer _gumjs_array_buffer_get_data (JSContextRef ctx,
    JSValueRef value, gsize * size);
G_GNUC_INTERNAL gboolean _gumjs_array_buffer_try_get_data (JSContextRef ctx,
    JSValueRef value, gpointer * data, gsize * size, JSValueRef * exception);

G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get (JSContextRef ctx,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get_opt (JSContextRef ctx,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);

G_GNUC_INTERNAL void _gumjs_throw (JSContextRef ctx, JSValueRef * exception,
    const gchar * format, ...);
G_GNUC_INTERNAL void _gumjs_throw_native (JSContextRef ctx,
    JSValueRef * exception, GumExceptionDetails * details,
    GumScriptCore * core);

G_END_DECLS

#endif
