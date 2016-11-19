/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_CORE_H__
#define __GUM_V8_CORE_H__

#include "gumscriptscheduler.h"
#include "gumv8script.h"
#include "gumv8scriptbackend.h"

#include <gum/gumexceptor.h>
#include <gum/gumprocess.h>
#include <v8.h>

#define GUMJS_NATIVE_POINTER_VALUE(o) \
    (o)->GetInternalField (0).As<External> ()->Value ()
#define GUMJS_CPU_CONTEXT_VALUE(o) \
    ((GumCpuContext *) (o)->GetInternalField (0).As<External> ()->Value ())

#ifdef G_OS_WIN32
# define GUMJS_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUMJS_SYSTEM_ERROR_FIELD "errno"
#endif

struct GumV8ExceptionSink;
struct GumV8MessageSink;

template <typename T>
struct GumPersistent
{
  typedef v8::Persistent<T, v8::CopyablePersistentTraits<T> > type;
};

typedef void (* GumV8FlushNotify) (GumV8Script * script);
typedef void (* GumV8MessageEmitter) (GumV8Script * script,
    const gchar * message, GBytes * data);

struct GumV8Core
{
  GumV8Script * script;
  GumV8ScriptBackend * backend;
  const gchar * runtime_source_map;
  GumV8Core * core;
  GumV8MessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  v8::Isolate * isolate;

  volatile guint usage_count;
  volatile GumV8FlushNotify flush_notify;

  GMainLoop * event_loop;
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

  GQueue * tick_callbacks;

  GSList * scheduled_callbacks;
  guint last_callback_id;

  GHashTable * native_functions;

  GHashTable * native_callbacks;

  GHashTable * native_resources;

  GHashTable * source_maps;

  GumPersistent<v8::FunctionTemplate>::type * int64;
  GumPersistent<v8::Object>::type * int64_value;

  GumPersistent<v8::FunctionTemplate>::type * uint64;
  GumPersistent<v8::Object>::type * uint64_value;

  GumPersistent<v8::FunctionTemplate>::type * native_pointer;
  GumPersistent<v8::Object>::type * native_pointer_value;
  GumPersistent<v8::String>::type * handle_key;

  GumPersistent<v8::FunctionTemplate>::type * native_function;
  GumPersistent<v8::Object>::type * native_return_value;
  GumPersistent<v8::String>::type * value_key;
  GumPersistent<v8::String>::type * system_error_key;

  GumPersistent<v8::FunctionTemplate>::type * cpu_context;
  GumPersistent<v8::Object>::type * cpu_context_value;

  GumPersistent<v8::FunctionTemplate>::type * source_map;
};

struct GumV8NativeResource
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GDestroyNotify notify;
  GumV8Core * core;
};

struct GumV8ByteArray
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GumV8Core * core;
};

G_GNUC_INTERNAL void _gum_v8_core_init (GumV8Core * self,
    GumV8Script * script, const gchar * runtime_source_map,
    GumV8MessageEmitter message_emitter, GumScriptScheduler * scheduler,
    v8::Isolate * isolate, v8::Handle<v8::ObjectTemplate> scope);
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

G_GNUC_INTERNAL void _gum_v8_core_post (GumV8Core * self, const gchar * message,
    GBytes * data);

G_GNUC_INTERNAL void _gum_v8_core_push_job (GumV8Core * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

#endif
