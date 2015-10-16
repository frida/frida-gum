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

G_GNUC_INTERNAL gchar * _gum_script_string_get (JSStringRef str);
G_GNUC_INTERNAL gchar * _gum_script_string_from_value (JSContextRef ctx,
    JSValueRef value);
G_GNUC_INTERNAL JSValueRef _gum_script_string_to_value (JSContextRef ctx,
    const gchar * str);

G_GNUC_INTERNAL JSValueRef _gum_script_object_get (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL guint _gum_script_object_get_uint (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL gchar * _gum_script_object_get_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key);
G_GNUC_INTERNAL void _gum_script_object_set (JSContextRef ctx,
    JSObjectRef object, const gchar * key, JSValueRef value);
G_GNUC_INTERNAL void _gum_script_object_set_string (JSContextRef ctx,
    JSObjectRef object, const gchar * key, const gchar * value);
G_GNUC_INTERNAL void _gum_script_object_set_function (JSContextRef ctx,
    JSObjectRef object, const gchar * key,
    JSObjectCallAsFunctionCallback callback);

G_GNUC_INTERNAL GBytes * _gum_script_byte_array_get (JSContextRef ctx,
    JSValueRef value, JSValueRef * exception);
G_GNUC_INTERNAL GBytes * _gum_script_byte_array_try_get (JSContextRef ctx,
    JSValueRef value);

G_GNUC_INTERNAL gboolean _gum_script_callback_get_opt (JSContextRef ctx,
    JSValueRef value, JSObjectRef * callback, JSValueRef * exception);

G_GNUC_INTERNAL void _gum_script_throw (JSContextRef ctx,
    JSValueRef * exception, const gchar * format, ...);

G_END_DECLS

#endif
