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
typedef struct _GumScriptWeakRef GumScriptWeakRef;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumExceptionSink GumExceptionSink;
typedef struct _GumMessageSink GumMessageSink;

typedef struct _GumNativeResource GumNativeResource;

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

  GumExceptionSink * unhandled_exception_sink;
  GumMessageSink * incoming_message_sink;

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  GHashTable * native_resources;

  JSClassRef native_pointer;
  JSObjectRef array_buffer;
};

struct _GumScriptScope
{
  GumScriptCore * core;
  JSValueRef exception;
};

struct _GumNativeResource
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

G_GNUC_INTERNAL void _gum_script_scope_enter (GumScriptScope * self,
    GumScriptCore * core);
G_GNUC_INTERNAL void _gum_script_scope_flush (GumScriptScope * self);
G_GNUC_INTERNAL void _gum_script_scope_leave (GumScriptScope * self);

G_GNUC_INTERNAL void _gum_script_panic (JSValueRef exception, JSContextRef ctx);

G_END_DECLS

#endif
