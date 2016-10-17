/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_VALUE_H__
#define __GUM_V8_VALUE_H__

#include "gumv8core.h"

#include <v8.h>

struct GumV8Args
{
  const v8::FunctionCallbackInfo<v8::Value> * info;
  GumV8Core * core;
};

struct GumV8Property
{
  const gchar * name;
  v8::AccessorGetterCallback getter;
  v8::AccessorSetterCallback setter;
};

struct GumV8Function
{
  const gchar * name;
  v8::FunctionCallback callback;
};

G_GNUC_INTERNAL gboolean _gum_v8_args_parse (const GumV8Args * args,
    const gchar * format, ...);

G_GNUC_INTERNAL v8::Local<v8::String> _gum_v8_string_new_from_ascii (
    const gchar * str, v8::Isolate * isolate);

G_GNUC_INTERNAL GBytes * _gum_v8_byte_array_get (v8::Handle<v8::Value> value,
    GumV8Core * core);
G_GNUC_INTERNAL GBytes * _gum_v8_byte_array_try_get (
    v8::Handle<v8::Value> value, GumV8Core * core);

G_GNUC_INTERNAL GumV8NativeResource * _gum_v8_native_resource_new (
    gpointer data, gsize size, GDestroyNotify notify, GumV8Core * core);
G_GNUC_INTERNAL void _gum_v8_native_resource_free (GumV8NativeResource * block);

G_GNUC_INTERNAL gboolean _gum_v8_size_get (v8::Handle<v8::Value> value,
    gsize * target, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_ssize_get (v8::Handle<v8::Value> value,
    gssize * target, GumV8Core * core);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_int64_new (gint64 value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_int64_get (v8::Handle<v8::Value> value,
    gint64 * target, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_int64_parse (v8::Handle<v8::Value> value,
    gint64 * target, GumV8Core * core);
G_GNUC_INTERNAL gint64 _gum_v8_int64_get_value (v8::Handle<v8::Object> object);
G_GNUC_INTERNAL void _gum_v8_int64_set_value (v8::Handle<v8::Object> object,
    gint64 value, v8::Isolate * isolate);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_uint64_new (guint64 value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_uint64_get (v8::Handle<v8::Value> value,
    guint64 * target, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_uint64_parse (v8::Handle<v8::Value> value,
    guint64 * target, GumV8Core * core);
G_GNUC_INTERNAL guint64 _gum_v8_uint64_get_value (
    v8::Handle<v8::Object> object);
G_GNUC_INTERNAL void _gum_v8_uint64_set_value (v8::Handle<v8::Object> object,
    guint64 value, v8::Isolate * isolate);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_native_pointer_new (
    gpointer address, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_native_pointer_get (
    v8::Handle<v8::Value> value, gpointer * target, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_native_pointer_parse (
    v8::Handle<v8::Value> value, gpointer * target, GumV8Core * core);

G_GNUC_INTERNAL void _gum_v8_throw (v8::Isolate * isolate, const gchar * format,
    ...);
G_GNUC_INTERNAL void _gum_v8_throw_literal (v8::Isolate * isolate,
    const gchar * message);
G_GNUC_INTERNAL void _gum_v8_throw_ascii (v8::Isolate * isolate,
    const gchar * format, ...);
G_GNUC_INTERNAL void _gum_v8_throw_ascii_literal (v8::Isolate * isolate,
    const gchar * message);
G_GNUC_INTERNAL void _gum_v8_throw_native (GumExceptionDetails * details,
    GumV8Core * core);
G_GNUC_INTERNAL void _gum_v8_parse_exception_details (
    GumExceptionDetails * details, v8::Local<v8::Object> & exception,
    v8::Local<v8::Object> & cpu_context, GumV8Core * core);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_cpu_context_new (
    const GumCpuContext * cpu_context, GumV8Core * core);
G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_cpu_context_new (
    GumCpuContext * cpu_context, GumV8Core * core);
G_GNUC_INTERNAL void _gum_v8_cpu_context_free_later (
    GumPersistent<v8::Object>::type * cpu_context, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_cpu_context_get (
    v8::Handle<v8::Value> value, GumCpuContext ** target, GumV8Core * core);

G_GNUC_INTERNAL const gchar * _gum_v8_thread_state_to_string (
    GumThreadState state);
G_GNUC_INTERNAL const gchar * _gum_v8_memory_operation_to_string (
    GumMemoryOperation operation);

G_GNUC_INTERNAL gboolean _gum_v8_object_set (v8::Handle<v8::Object> object,
    const gchar * key, v8::Handle<v8::Value> value, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_object_set_uint (v8::Handle<v8::Object> object,
    const gchar * key, guint value, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_object_set_pointer (
    v8::Handle<v8::Object> object, const gchar * key, gpointer value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_object_set_pointer (
    v8::Handle<v8::Object> object, const gchar * key, GumAddress value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_object_set_ascii (
    v8::Handle<v8::Object> object, const gchar * key, const gchar * value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_object_set_utf8 (v8::Handle<v8::Object> object,
    const gchar * key, const gchar * value, GumV8Core * core);

G_GNUC_INTERNAL gboolean _gum_v8_callbacks_get (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_callbacks_get_opt (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumV8Core * core);

G_GNUC_INTERNAL gboolean _gum_v8_page_protection_get (
    v8::Handle<v8::Value> prot_val, GumPageProtection * prot,
    GumV8Core * core);

G_GNUC_INTERNAL v8::Local<v8::ObjectTemplate> _gum_v8_create_module (
    const gchar * name, v8::Handle<v8::ObjectTemplate> scope,
    v8::Isolate * isolate);
G_GNUC_INTERNAL void _gum_v8_module_add (v8::Handle<v8::External> module,
    v8::Handle<v8::ObjectTemplate> object, const GumV8Property * properties,
    v8::Isolate * isolate);
G_GNUC_INTERNAL void _gum_v8_module_add (v8::Handle<v8::External> module,
    v8::Handle<v8::ObjectTemplate> object, const GumV8Function * functions,
    v8::Isolate * isolate);
G_GNUC_INTERNAL v8::Local<v8::FunctionTemplate> _gum_v8_create_class (
    const gchar * name, v8::FunctionCallback ctor,
    v8::Handle<v8::ObjectTemplate> scope, v8::Handle<v8::External> module,
    v8::Isolate * isolate);
G_GNUC_INTERNAL void _gum_v8_class_add (v8::Handle<v8::FunctionTemplate> klass,
    const GumV8Function * functions, v8::Handle<v8::External> module,
    v8::Isolate * isolate);

#endif
