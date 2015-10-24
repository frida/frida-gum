/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_CORE_H__
#define __GUM_JSCRIPT_CORE_H__

#include "gumscript.h"
#include "gumscriptscheduler.h"

#include <gum/gumexceptor.h>
#include <JavaScriptCore/JavaScriptCore.h>

G_BEGIN_DECLS

typedef struct _GumScriptCore GumScriptCore;
typedef struct _GumScriptScope GumScriptScope;
typedef struct _GumScriptYield GumScriptYield;
typedef struct _GumScriptWeakRef GumScriptWeakRef;

typedef struct _GumScriptScheduledCallback GumScriptScheduledCallback;
typedef struct _GumScriptExceptionSink GumScriptExceptionSink;
typedef struct _GumScriptMessageSink GumScriptMessageSink;

typedef struct _GumScriptNativePointer GumScriptNativePointer;
typedef struct _GumScriptCpuContext GumScriptCpuContext;
typedef guint GumScriptCpuContextAccess;
typedef struct _GumScriptNativeResource GumScriptNativeResource;

typedef void (* GumScriptWeakNotify) (gpointer data);
typedef void (* GumScriptCoreMessageEmitter) (GumScript * script,
    const gchar * message, GBytes * data);

struct _GumScriptCore
{
  GumScript * script;
  GumScriptCoreMessageEmitter message_emitter;
  GumScriptScheduler * scheduler;
  GumExceptor * exceptor;
  JSContextRef ctx;

  GMutex mutex;

  GCond event_cond;
  volatile guint event_count;

  GumScriptExceptionSink * unhandled_exception_sink;
  GumScriptMessageSink * incoming_message_sink;

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  GHashTable * native_resources;

  JSClassRef native_pointer;
  JSClassRef cpu_context;
  JSObjectRef array_buffer;
};

struct _GumScriptScope
{
  GumScriptCore * core;
  JSValueRef exception;
};

struct _GumScriptYield
{
  GumScriptCore * core;
};

struct _GumScriptNativePointer
{
  gsize instance_size;
  gpointer value;
};

struct _GumScriptCpuContext
{
  GumCpuContext * handle;
  GumScriptCpuContextAccess access;
  GumCpuContext storage;
};

enum _GumScriptCpuContextAccess
{
  GUM_CPU_CONTEXT_READONLY = 1,
  GUM_CPU_CONTEXT_READWRITE
};

struct _GumScriptNativeResource
{
  GumScriptWeakRef * weak_ref;
  gpointer data;
  GDestroyNotify notify;
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_core_init (GumScriptCore * self,
    GumScript * script, GumScriptCoreMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, JSContextRef ctx, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_core_flush (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_dispose (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_finalize (GumScriptCore * self);

G_GNUC_INTERNAL void _gum_script_core_emit_message (GumScriptCore * self,
    const gchar * message, GBytes * data);
G_GNUC_INTERNAL void _gum_script_core_post_message (GumScriptCore * self,
    const gchar * message);

G_GNUC_INTERNAL void _gum_script_core_push_job (GumScriptCore * self,
    GumScriptJobFunc job_func, gpointer data, GDestroyNotify data_destroy);

G_GNUC_INTERNAL void _gum_script_scope_enter (GumScriptScope * self,
    GumScriptCore * core);
G_GNUC_INTERNAL void _gum_script_scope_flush (GumScriptScope * self);
G_GNUC_INTERNAL void _gum_script_scope_leave (GumScriptScope * self);

G_GNUC_INTERNAL void _gum_script_yield_begin (GumScriptYield * self,
    GumScriptCore * core);
G_GNUC_INTERNAL void _gum_script_yield_end (GumScriptYield * self);

G_GNUC_INTERNAL void _gum_script_panic (JSValueRef exception, JSContextRef ctx);

G_END_DECLS

#endif
