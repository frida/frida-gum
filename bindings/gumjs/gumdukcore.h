/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_CORE_H__
#define __GUM_DUK_CORE_H__

#include "duktape.h"
#include "gumdukscript.h"
#include "gumdukscriptbackend.h"
#include "gumscriptscheduler.h"

#include <gum/gumexceptor.h>

#define GUM_DUK_SCOPE_INIT(C) { C, 0, (C)->current_ctx, NULL }

#ifdef G_OS_WIN32
# define GUMJS_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUMJS_SYSTEM_ERROR_FIELD "errno"
#endif

G_BEGIN_DECLS

typedef struct _GumDukCore GumDukCore;
typedef struct _GumDukInterceptor GumDukInterceptor;
typedef struct _GumDukScope GumDukScope;
typedef gpointer GumDukHeapPtr;
typedef struct _GumDukWeakRef GumDukWeakRef;

typedef struct _GumDukScheduledCallback GumDukScheduledCallback;
typedef struct _GumDukExceptionSink GumDukExceptionSink;
typedef struct _GumDukMessageSink GumDukMessageSink;

typedef struct _GumDukInt64 GumDukInt64;
typedef struct _GumDukUInt64 GumDukUInt64;
typedef struct _GumDukNativePointer GumDukNativePointer;
typedef struct _GumDukNativePointerImpl GumDukNativePointerImpl;
typedef struct _GumDukCpuContext GumDukCpuContext;
typedef guint GumDukCpuContextAccess;
typedef struct _GumDukNativeResource GumDukNativeResource;

typedef void (* GumDukWeakNotify) (gpointer data);
typedef void (* GumDukFlushNotify) (GumDukScript * script);
typedef void (* GumDukMessageEmitter) (GumDukScript * script,
    const gchar * message, GBytes * data);

struct _GumDukCore
{
  GumDukScript * script;
  GumDukScriptBackend * backend;
  const gchar * runtime_source_map;
  GumDukInterceptor * interceptor;
  GumDukMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  duk_context * heap_ctx;
  duk_context * current_ctx;

  GRecMutex mutex;
  volatile guint usage_count;
  volatile guint mutex_depth;
  volatile gboolean heap_thread_in_use;
  volatile GumDukFlushNotify flush_notify;

  GMainLoop * event_loop;
  GMutex event_mutex;
  GCond event_cond;
  volatile guint event_count;

  GumDukExceptionSink * unhandled_exception_sink;
  GumDukMessageSink * incoming_message_sink;

  GumDukHeapPtr on_global_enumerate;
  GumDukHeapPtr on_global_get;
  GumDukHeapPtr global_receiver;

  GHashTable * weak_refs;
  guint last_weak_ref_id;

  GQueue * tick_callbacks;

  GSList * scheduled_callbacks;
  guint last_callback_id;

  GumDukHeapPtr int64;
  GumDukHeapPtr uint64;
  GumDukHeapPtr native_pointer;
  GumDukHeapPtr native_resource;
  GumDukHeapPtr native_function;
  GumDukHeapPtr native_function_prototype;
  GumDukHeapPtr system_function;
  GumDukHeapPtr system_function_prototype;
  GumDukHeapPtr cpu_context;
  GumDukHeapPtr source_map;

  GumDukNativePointerImpl * cached_native_pointers;
};

struct _GumDukScope
{
  GumDukCore * core;
  guint previous_mutex_depth;
  duk_context * ctx;
  GumDukHeapPtr exception;
  duk_thread_state thread_state;
};

struct _GumDukInt64
{
  gint64 value;
};

struct _GumDukUInt64
{
  guint64 value;
};

struct _GumDukNativePointer
{
  gpointer value;
};

struct _GumDukNativePointerImpl
{
  GumDukNativePointer parent;

  GumDukHeapPtr object;
  gchar * id;
  GumDukNativePointerImpl * next;
};

struct _GumDukCpuContext
{
  GumDukHeapPtr object;
  GumCpuContext * handle;
  GumDukCpuContextAccess access;
  GumCpuContext storage;
};

enum _GumDukCpuContextAccess
{
  GUM_CPU_CONTEXT_READONLY = 1,
  GUM_CPU_CONTEXT_READWRITE
};

struct _GumDukNativeResource
{
  GumDukNativePointer parent;

  GDestroyNotify notify;
};

G_GNUC_INTERNAL void _gum_duk_core_init (GumDukCore * self,
    GumDukScript * script, const gchar * runtime_source_map,
    GumDukInterceptor * interceptor, GumDukMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, duk_context * ctx);
G_GNUC_INTERNAL gboolean _gum_duk_core_flush (GumDukCore * self,
    GumDukFlushNotify flush_notify);
G_GNUC_INTERNAL void _gum_duk_core_dispose (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_finalize (GumDukCore * self);

G_GNUC_INTERNAL void _gum_duk_core_pin (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_unpin (GumDukCore * self);

G_GNUC_INTERNAL void _gum_duk_core_post (GumDukCore * self,
    const gchar * message, GBytes * data);

G_GNUC_INTERNAL void _gum_duk_core_push_job (GumDukCore * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

G_GNUC_INTERNAL duk_context * _gum_duk_scope_enter (GumDukScope * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_scope_suspend (GumDukScope * self);
G_GNUC_INTERNAL void _gum_duk_scope_resume (GumDukScope * self);
G_GNUC_INTERNAL gboolean _gum_duk_scope_call (GumDukScope * self,
    duk_idx_t nargs);
G_GNUC_INTERNAL gboolean _gum_duk_scope_call_method (GumDukScope * self,
    duk_idx_t nargs);
G_GNUC_INTERNAL gboolean _gum_duk_scope_call_sync (GumDukScope * self,
    duk_idx_t nargs);
G_GNUC_INTERNAL void _gum_duk_scope_flush (GumDukScope * self);
G_GNUC_INTERNAL void _gum_duk_scope_leave (GumDukScope * self);

G_END_DECLS

#endif
