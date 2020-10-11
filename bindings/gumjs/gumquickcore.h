/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_CORE_H__
#define __GUM_QUICK_CORE_H__

#include "gumquickscript.h"
#include "gumquickscriptbackend.h"

#include <gum/gumexceptor.h>

#define GUM_QUICK_SCOPE_INIT(C) { C, NULL, }

#ifdef HAVE_WINDOWS
# define GUMJS_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUMJS_SYSTEM_ERROR_FIELD "errno"
#endif

G_BEGIN_DECLS

typedef struct _GumQuickCore GumQuickCore;
typedef struct _GumQuickInterceptor GumQuickInterceptor;
typedef struct _GumQuickStalker GumQuickStalker;
typedef struct _GumQuickScope GumQuickScope;
typedef struct _GumQuickWeakRef GumQuickWeakRef;

typedef struct _GumQuickScheduledCallback GumQuickScheduledCallback;
typedef struct _GumQuickExceptionSink GumQuickExceptionSink;
typedef struct _GumQuickMessageSink GumQuickMessageSink;

typedef struct _GumQuickInt64 GumQuickInt64;
typedef struct _GumQuickUInt64 GumQuickUInt64;
typedef struct _GumQuickNativePointer GumQuickNativePointer;
typedef struct _GumQuickCpuContext GumQuickCpuContext;
typedef guint GumQuickCpuContextAccess;
typedef struct _GumQuickNativeResource GumQuickNativeResource;
typedef struct _GumQuickKernelResource GumQuickKernelResource;

typedef void (* GumQuickWeakNotify) (gpointer data);
typedef void (* GumQuickFlushNotify) (GumQuickScript * script);
typedef void (* GumQuickMessageEmitter) (GumQuickScript * script,
    const gchar * message, GBytes * data);
typedef void (* GumQuickKernelNotify) (guint64 data);

struct _GumQuickCore
{
  GumQuickScript * script;
  GumQuickScriptBackend * backend;
  const gchar * runtime_source_map;
  GumQuickInterceptor * interceptor;
  GumQuickStalker * stalker;
  GumQuickMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  JSRuntime * rt;
  JSContext * ctx;
  GHashTable * module_data;
  GumQuickScope * current_scope;

  GRecMutex * mutex;
  volatile guint usage_count;
  volatile guint mutex_depth;
  volatile GumQuickFlushNotify flush_notify;

  GMainLoop * event_loop;
  GMutex event_mutex;
  GCond event_cond;
  volatile guint event_count;
  volatile gboolean event_source_available;

  GumQuickExceptionSink * unhandled_exception_sink;
  GumQuickMessageSink * incoming_message_sink;

  GHashTable * weak_refs;
  guint next_weak_ref_id;

  GHashTable * scheduled_callbacks;
  guint next_callback_id;

  JSClassID weak_ref_class;
  JSClassID int64_class;
  JSClassID uint64_class;
  JSClassID native_pointer_class;
  JSValue native_pointer_proto;
  GHashTable * native_pointer_class_ids;
  JSClassID native_resource_class;
  JSClassID kernel_resource_class;
  JSClassID native_function_class;
  JSClassID system_function_class;
  JSClassID native_callback_class;
  JSClassID cpu_context_class;
  JSClassID source_map_class;
  JSValue source_map_ctor;
};

struct _GumQuickScope
{
  GumQuickCore * core;
  GumQuickScope * previous_scope;
  guint previous_mutex_depth;
  JSRuntimeThreadState thread_state;

  GQueue tick_callbacks;
  GQueue scheduled_sources;

  gint pending_stalker_level;
  GumStalkerTransformer * pending_stalker_transformer;
  GumEventSink * pending_stalker_sink;
};

struct _GumQuickInt64
{
  gint64 value;
};

struct _GumQuickUInt64
{
  guint64 value;
};

struct _GumQuickNativePointer
{
  gpointer value;
};

struct _GumQuickCpuContext
{
  JSValue wrapper;
  GumCpuContext * handle;
  GumQuickCpuContextAccess access;
  GumCpuContext storage;

  GumQuickCore * core;
};

enum _GumQuickCpuContextAccess
{
  GUM_CPU_CONTEXT_READONLY = 1,
  GUM_CPU_CONTEXT_READWRITE
};

struct _GumQuickNativeResource
{
  GumQuickNativePointer native_pointer;

  GDestroyNotify notify;
};

struct _GumQuickKernelResource
{
  GumQuickUInt64 u64;

  GumQuickKernelNotify notify;
};

G_GNUC_INTERNAL void _gum_quick_core_init (GumQuickCore * self,
    GumQuickScript * script, JSContext * ctx, JSValue ns, GRecMutex * mutex,
    const gchar * runtime_source_map, GumQuickInterceptor * interceptor,
    GumQuickStalker * stalker, GumQuickMessageEmitter message_emitter,
    GumScriptScheduler * scheduler);
G_GNUC_INTERNAL gboolean _gum_quick_core_flush (GumQuickCore * self,
    GumQuickFlushNotify flush_notify);
G_GNUC_INTERNAL void _gum_quick_core_dispose (GumQuickCore * self);
G_GNUC_INTERNAL void _gum_quick_core_finalize (GumQuickCore * self);

G_GNUC_INTERNAL void _gum_quick_core_pin (GumQuickCore * self);
G_GNUC_INTERNAL void _gum_quick_core_unpin (GumQuickCore * self);

G_GNUC_INTERNAL void _gum_quick_core_post (GumQuickCore * self,
    const gchar * message, GBytes * data);

G_GNUC_INTERNAL void _gum_quick_core_push_job (GumQuickCore * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

G_GNUC_INTERNAL void _gum_quick_core_store_module_data (GumQuickCore * self,
    const gchar * key, gpointer value);
G_GNUC_INTERNAL gpointer _gum_quick_core_load_module_data (GumQuickCore * self,
    const gchar * key);

G_GNUC_INTERNAL gboolean _gum_quick_core_is_native_pointer (GumQuickCore * self,
    JSClassID class_id);
G_GNUC_INTERNAL void _gum_quick_core_create_native_pointer_subclass (
    GumQuickCore * self, const JSClassDef * class_def, JSClassID * class_id,
    JSValue * prototype);

G_GNUC_INTERNAL void _gum_quick_scope_enter (GumQuickScope * self,
    GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_scope_suspend (GumQuickScope * self);
G_GNUC_INTERNAL void _gum_quick_scope_resume (GumQuickScope * self);
G_GNUC_INTERNAL JSValue _gum_quick_scope_call (GumQuickScope * self,
    JSValueConst func_obj, JSValueConst this_obj, int argc,
    JSValueConst * argv);
G_GNUC_INTERNAL gboolean _gum_quick_scope_call_void (GumQuickScope * self,
    JSValueConst func_obj, JSValueConst this_obj, int argc,
    JSValueConst * argv);
G_GNUC_INTERNAL void _gum_quick_scope_catch_and_emit (GumQuickScope * self);
G_GNUC_INTERNAL void _gum_quick_scope_perform_pending_io (GumQuickScope * self);
G_GNUC_INTERNAL void _gum_quick_scope_leave (GumQuickScope * self);

G_END_DECLS

#endif
