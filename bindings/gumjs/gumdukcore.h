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

#define GUM_DUK_SCOPE_INIT(C) { C, NULL }

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
typedef void (* GumDukMessageEmitter) (GumDukScript * script,
    const gchar * message, GBytes * data);

struct _GumDukCore
{
  GumDukScript * script;
  GumDukScriptBackend * backend;
  GumDukInterceptor * interceptor;
  GAsyncQueue * incoming_messages;
  GumDukMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  duk_context * ctx;

  GRecMutex mutex;

  GumDukExceptionSink * unhandled_exception_sink;
  GumDukMessageSink * incoming_message_sink;

  GHashTable * weak_refs;
  guint last_weak_ref_id;

  GSList * scheduled_callbacks;
  guint last_callback_id;

  GumDukHeapPtr int64;
  GumDukHeapPtr uint64;
  GumDukHeapPtr native_pointer;
  GumDukHeapPtr native_resource;
  GumDukHeapPtr native_function;
  GumDukHeapPtr native_function_prototype;
  GumDukHeapPtr cpu_context;

  GumDukNativePointerImpl * cached_native_pointers;
};

struct _GumDukScope
{
  GumDukCore * core;
  GumDukHeapPtr exception;
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
    GumDukScript * script, GumDukInterceptor * interceptor,
    GAsyncQueue * incoming_messages, GumDukMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_core_flush (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_dispose (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_finalize (GumDukCore * self);

G_GNUC_INTERNAL void _gum_duk_core_absorb_messages (GumDukCore * self);

G_GNUC_INTERNAL void _gum_duk_core_push_job (GumDukCore * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

G_GNUC_INTERNAL void _gum_duk_scope_enter (GumDukScope * self,
    GumDukCore * core);
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
