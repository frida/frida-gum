/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_CORE_H__
#define __GUM_V8_CORE_H__

#define GUMJS_NATIVE_POINTER_VALUE(o) \
    (o)->GetInternalField (0).As<External> ()->Value ()
#define GUMJS_CPU_CONTEXT_VALUE(o) \
    static_cast<GumCpuContext *> ( \
        (o)->GetInternalField (0).As<External> ()->Value ())

#include "gumscriptscheduler.h"
#include "gumv8script.h"
#include "gumv8scriptbackend.h"

#include <gum/gumexceptor.h>
#include <gum/gumprocess.h>
#include <v8.h>

typedef struct _GumV8Core GumV8Core;

typedef struct _GumV8ScheduledCallback GumV8ScheduledCallback;
typedef struct _GumV8ExceptionSink GumV8ExceptionSink;
typedef struct _GumV8MessageSink GumV8MessageSink;

typedef struct _GumV8NativeResource GumV8NativeResource;
typedef struct _GumV8ByteArray GumV8ByteArray;

template <typename T>
struct GumPersistent
{
  typedef v8::Persistent<T, v8::CopyablePersistentTraits<T> > type;
};

typedef void (* GumV8FlushNotify) (GumV8Script * script);
typedef void (* GumV8MessageEmitter) (GumV8Script * script,
    const gchar * message, GBytes * data);

struct _GumV8Core
{
  GumV8Script * script;
  GumV8ScriptBackend * backend;
  GumV8MessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  v8::Isolate * isolate;

  volatile guint usage_count;
  volatile GumV8FlushNotify flush_notify;

  GMutex event_mutex;
  GCond event_cond;
  volatile guint event_count;

  GumV8ExceptionSink * unhandled_exception_sink;
  GumV8MessageSink * incoming_message_sink;

  GumPersistent<v8::Function>::type * on_global_enumerate;
  GumPersistent<v8::Function>::type * on_global_get;
  GumPersistent<v8::Object>::type * global_receiver;

  GHashTable * weak_refs;
  guint last_weak_ref_id;

  GSList * scheduled_callbacks;
  guint last_callback_id;

  GHashTable * native_functions;

  GHashTable * native_callbacks;

  GHashTable * native_resources;

  GumPersistent<v8::FunctionTemplate>::type * int64;
  GumPersistent<v8::Object>::type * int64_value;

  GumPersistent<v8::FunctionTemplate>::type * uint64;
  GumPersistent<v8::Object>::type * uint64_value;

  GumPersistent<v8::FunctionTemplate>::type * native_pointer;
  GumPersistent<v8::Object>::type * native_pointer_value;
  GumPersistent<v8::String>::type * handle_key;

  GumPersistent<v8::FunctionTemplate>::type * cpu_context;
  GumPersistent<v8::Object>::type * cpu_context_value;
};

struct _GumV8NativeResource
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GDestroyNotify notify;
  GumV8Core * core;
};

struct _GumV8ByteArray
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GumV8Core * core;
};

G_GNUC_INTERNAL void _gum_v8_core_init (GumV8Core * self,
    GumV8Script * script, GumV8MessageEmitter message_emitter,
    GumScriptScheduler * scheduler, v8::Isolate * isolate,
    v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_core_realize (GumV8Core * self);
G_GNUC_INTERNAL gboolean _gum_v8_core_flush (GumV8Core * self,
    GumV8FlushNotify flush_notify);
G_GNUC_INTERNAL void _gum_v8_core_notify_flushed (GumV8Core * self,
    GumV8FlushNotify func);
G_GNUC_INTERNAL void _gum_v8_core_dispose (GumV8Core * self);
G_GNUC_INTERNAL void _gum_v8_core_finalize (GumV8Core * self);

G_GNUC_INTERNAL void _gum_v8_core_pin (GumV8Core * self);
G_GNUC_INTERNAL void _gum_v8_core_unpin (GumV8Core * self);

G_GNUC_INTERNAL void _gum_v8_core_on_unhandled_exception (
    GumV8Core * self, v8::Handle<v8::Value> exception);

G_GNUC_INTERNAL void _gum_v8_core_post_message (GumV8Core * self,
    const gchar * message);

G_GNUC_INTERNAL void _gum_v8_core_push_job (GumV8Core * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

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

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_uint64_new (guint64 value,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_uint64_get (v8::Handle<v8::Value> value,
    guint64 * target, GumV8Core * core);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_v8_native_pointer_new (
    gpointer address, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_native_pointer_get (
    v8::Handle<v8::Value> value, gpointer * target, GumV8Core * core);
G_GNUC_INTERNAL gboolean _gum_v8_native_pointer_parse (
    v8::Handle<v8::Value> value, gpointer * target, GumV8Core * core);

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

#endif
