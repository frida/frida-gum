/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_CORE_H__
#define __GUM_DUKRIPT_CORE_H__

#include "duktape.h"
#include "gumdukscript.h"
#include "gumdukscriptbackend.h"
#include "gumscriptscheduler.h"

#include <gum/gumexceptor.h>

#define GUM_DUK_CORE_LOCK(core)   (g_mutex_lock (&(core)->mutex))
#define GUM_DUK_CORE_UNLOCK(core) (g_mutex_unlock (&(core)->mutex))

#define GUM_DUK_SCOPE_INIT(C) { C, NULL }

G_BEGIN_DECLS

typedef struct _GumDukCore GumDukCore;
typedef struct _GumDukScope GumDukScope;
typedef gpointer GumDukHeapPtr;
typedef struct _GumDukWeakRef GumDukWeakRef;

typedef struct _GumDukScheduledCallback GumDukScheduledCallback;
typedef struct _GumDukExceptionSink GumDukExceptionSink;
typedef struct _GumDukMessageSink GumDukMessageSink;

typedef struct _GumDukNativePointer GumDukNativePointer;
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
  GumDukMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  duk_context * ctx;

  GMutex mutex;

  GCond event_cond;
  volatile guint event_count;

  GumDukExceptionSink * unhandled_exception_sink;
  GumDukMessageSink * incoming_message_sink;

  GHashTable * weak_refs;
  guint last_weak_ref_id;

  GSList * scheduled_callbacks;
  guint last_callback_id;

  GHashTable * native_resources;

  GumDukHeapPtr native_pointer;
  GumDukHeapPtr native_function;
  GumDukHeapPtr native_function_prototype;
};

struct _GumDukScope
{
  GumDukCore * core;
  GumDukHeapPtr exception;
};

struct _GumDukNativePointer
{
  gpointer value;
};

struct _GumDukCpuContext
{
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
  GumDukWeakRef * weak_ref;
  gpointer data;
  GDestroyNotify notify;

  GumDukCore * core;
};

G_GNUC_INTERNAL void _gum_duk_core_init (GumDukCore * self,
    GumDukScript * script, GumDukMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, duk_context * ctx);
G_GNUC_INTERNAL void _gum_duk_core_flush (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_dispose (GumDukCore * self);
G_GNUC_INTERNAL void _gum_duk_core_finalize (GumDukCore * self);

G_GNUC_INTERNAL void _gum_duk_core_emit_message (GumDukCore * self,
    const gchar * message, GBytes * data);
G_GNUC_INTERNAL void _gum_duk_core_post_message (GumDukCore * self,
    const gchar * message);

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
