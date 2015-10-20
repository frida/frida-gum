/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_VALUE_H__
#define __GUM_JSCRIPT_VALUE_H__

#include <glib.h>
#include <JavaScriptCore/JavaScriptCore.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL gint _gumjs_int_from_value (JSContextRef ctx, JSValueRef value);
G_GNUC_INTERNAL gboolean _gumjs_try_int_from_value (JSContextRef ctx,
    JSValueRef value, gint * i, JSValueRef * exception);
G_GNUC_INTERNAL gchar * _gumjs_string_get (JSStringRef str);
G_GNUC_INTERNAL gchar * _gumjs_string_from_value (JSContextRef ctx,
    JSValueRef value);
G_GNUC_INTERNAL gboolean _gumjs_try_string_from_value (JSContextRef ctx,
    JSValueRef value, gchar ** str, JSValueRef * exception);
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

G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get (JSContextRef ctx,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get_opt (JSContextRef ctx,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);

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

G_GNUC_INTERNAL void _gumjs_throw (JSContextRef ctx, JSValueRef * exception,
    const gchar * format, ...);

G_END_DECLS

#endif
