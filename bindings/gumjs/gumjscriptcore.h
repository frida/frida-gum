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
typedef struct _GumScriptArgs GumScriptArgs;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumExceptionSink GumExceptionSink;
typedef struct _GumMessageSink GumMessageSink;

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

  JSClassRef native_pointer;
  JSObjectRef array_buffer;
};

struct _GumScriptScope
{
  GumScriptCore * core;
  JSValueRef exception;
};

struct _GumScriptArgs
{
  gsize count;
  const JSValueRef * values;
  JSValueRef * exception;

  JSContextRef ctx;
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
G_GNUC_INTERNAL void _gum_script_scope_leave (GumScriptScope * self);

G_GNUC_INTERNAL gboolean _gum_script_args_parse (const GumScriptArgs * self,
    const gchar * format, ...);

G_GNUC_INTERNAL JSValueRef _gumjs_native_pointer_new (GumScriptCore * core,
    gpointer address);
G_GNUC_INTERNAL gboolean _gumjs_native_pointer_get (GumScriptCore * core,
    JSValueRef value, gpointer * target, JSValueRef * exception);

G_GNUC_INTERNAL JSObjectRef _gumjs_array_buffer_new (GumScriptCore * core,
    gsize size);
G_GNUC_INTERNAL gpointer _gumjs_array_buffer_get_data (GumScriptCore * core,
    JSValueRef value, gsize * size);
G_GNUC_INTERNAL gboolean _gumjs_array_buffer_try_get_data (GumScriptCore * core,
    JSValueRef value, gpointer * data, gsize * size, JSValueRef * exception);

G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get (GumScriptCore * core,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);
G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get_opt (GumScriptCore * core,
    JSValueRef value, GBytes ** bytes, JSValueRef * exception);

G_GNUC_INTERNAL void _gumjs_throw_native (GumScriptCore * core,
    GumExceptionDetails * details, JSValueRef * exception);

G_GNUC_INTERNAL void _gum_script_panic (JSValueRef exception, JSContextRef ctx);

G_END_DECLS

#endif
