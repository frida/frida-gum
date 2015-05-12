/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_CORE_H__
#define __GUM_SCRIPT_CORE_H__

#define GUM_NATIVE_POINTER_VALUE(o) \
    (o)->GetInternalField (0).As<External> ()->Value ()
#define GUM_CPU_CONTEXT_VALUE(o) \
    static_cast<GumCpuContext *> ( \
        (o)->GetInternalField (0).As<External> ()->Value ())

#include "gumscript.h"
#include "gumscriptscheduler.h"

#include <v8.h>

typedef struct _GumScriptCore GumScriptCore;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumMessageSink GumMessageSink;

typedef struct _GumHeapBlock GumHeapBlock;
typedef struct _GumByteArray GumByteArray;

template <typename T>
struct GumPersistent
{
  typedef v8::Persistent<T, v8::CopyablePersistentTraits<T> > type;
};

typedef void (* GumScriptCoreMessageEmitter) (GumScript * script,
    const gchar * message, const guint8 * data, gint data_length);

struct _GumScriptCore
{
  GumScript * script;
  GumScriptCoreMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  v8::Isolate * isolate;

  GMutex mutex;

  GCond event_cond;
  volatile guint event_count;

  GumMessageSink * incoming_message_sink;

  GHashTable * weak_refs;
  volatile gint last_weak_ref_id;

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  GHashTable * native_functions;

  GHashTable * native_callbacks;

  GHashTable * byte_arrays;

  GHashTable * heap_blocks;

  GumPersistent<v8::FunctionTemplate>::type * native_pointer;
  GumPersistent<v8::Object>::type * native_pointer_value;
  GumPersistent<v8::String>::type * handle_key;

  GumPersistent<v8::FunctionTemplate>::type * cpu_context;
  GumPersistent<v8::Object>::type * cpu_context_value;
};

struct _GumHeapBlock
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GumScriptCore * core;
};

struct _GumByteArray
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_core_init (GumScriptCore * self,
    GumScript * script, GumScriptCoreMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, v8::Isolate * isolate,
    v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_core_realize (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_flush (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_dispose (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_finalize (GumScriptCore * self);

G_GNUC_INTERNAL void _gum_script_core_set_message_handler (GumScriptCore * self,
    GumScriptMessageHandler func, gpointer data, GDestroyNotify notify);
G_GNUC_INTERNAL void _gum_script_core_emit_message (GumScriptCore * self,
    const gchar * message, const guint8 * data, gint data_length);
G_GNUC_INTERNAL void _gum_script_core_post_message (GumScriptCore * self,
    const gchar * message);

G_GNUC_INTERNAL void _gum_script_core_push_job (GumScriptCore * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

G_GNUC_INTERNAL GumByteArray * _gum_byte_array_new (gpointer data, gsize size,
    GumScriptCore * core);
G_GNUC_INTERNAL void _gum_byte_array_free (GumByteArray * buffer);

G_GNUC_INTERNAL GumHeapBlock * _gum_heap_block_new (gpointer data,
    gsize size, GumScriptCore * core);
G_GNUC_INTERNAL void _gum_heap_block_free (GumHeapBlock * block);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_script_pointer_new (gpointer address,
    GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_pointer_get (v8::Handle<v8::Value> value,
    gpointer * target, GumScriptCore * core);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_script_cpu_context_new (
    const GumCpuContext * cpu_context, GumScriptCore * core);
G_GNUC_INTERNAL v8::Local<v8::Object> _gum_script_cpu_context_new (
    GumCpuContext * cpu_context, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_cpu_context_get (
    v8::Handle<v8::Value> value, GumCpuContext ** target, GumScriptCore * core);

G_GNUC_INTERNAL gboolean _gum_script_set (v8::Handle<v8::Object> object,
    const gchar * key, v8::Handle<v8::Value> value, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_set_uint (v8::Handle<v8::Object> object,
    const gchar * key, guint value, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_set_pointer (v8::Handle<v8::Object> object,
    const gchar * key, gpointer value, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_set_pointer (v8::Handle<v8::Object> object,
    const gchar * key, GumAddress value, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_set_ascii (v8::Handle<v8::Object> object,
    const gchar * key, const gchar * value, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_set_utf8 (v8::Handle<v8::Object> object,
    const gchar * key, const gchar * value, GumScriptCore * core);

G_GNUC_INTERNAL gboolean _gum_script_callbacks_get (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_callbacks_get_opt (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumScriptCore * core);

G_GNUC_INTERNAL gboolean _gum_script_page_protection_get (
    v8::Handle<v8::Value> prot_val, GumPageProtection * prot,
    GumScriptCore * core);

#endif
