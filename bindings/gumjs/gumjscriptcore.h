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

#define GUM_SCRIPT_CORE(P) \
  ((GumScriptCore *) (P))

#define GUM_JSC_CTX_GET_CORE(C) \
  GUM_SCRIPT_CORE (JSObjectGetPrivate (JSContextGetGlobalObject (C)))

#define GUM_DECLARE_JSC_CONSTRUCTOR(N) \
  static JSObjectRef N (JSContextRef ctx, JSObjectRef constructor, \
      size_t argument_count, const JSValueRef arguments[], \
      JSValueRef * exception)
#define GUM_DECLARE_JSC_FUNCTION(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef function, \
      JSObjectRef this_object, size_t argument_count, \
      const JSValueRef arguments[], JSValueRef * exception)
#define GUM_DECLARE_JSC_GETTER(N) \
  static JSValueRef N (JSContextRef ctx, JSObjectRef object, \
      JSStringRef property_name, JSValueRef * exception)

#define GUM_DEFINE_JSC_CONSTRUCTOR(N) \
  static JSObjectRef \
  N (JSContextRef ctx, \
     JSObjectRef constructor, \
     size_t argument_count, \
     const JSValueRef arguments[], \
     JSValueRef * exception)
#define GUM_DEFINE_JSC_FUNCTION(N) \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef function, \
     JSObjectRef this_object, \
     size_t argument_count, \
     const JSValueRef arguments[], \
     JSValueRef * exception)
#define GUM_DEFINE_JSC_GETTER(N) \
  static JSValueRef \
  N (JSContextRef ctx, \
     JSObjectRef object, \
     JSStringRef property_name, \
     JSValueRef * exception)

typedef struct _GumScriptCore GumScriptCore;

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

  GumMessageSink * incoming_message_sink;

  JSClassRef native_pointer;
};

G_GNUC_INTERNAL void _gum_script_core_init (GumScriptCore * self,
    GumScript * script, GumScriptCoreMessageEmitter message_emitter,
    GumScriptScheduler * scheduler, JSContextRef ctx, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_core_realize (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_flush (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_dispose (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_finalize (GumScriptCore * self);

G_GNUC_INTERNAL void _gum_script_core_emit_message (GumScriptCore * self,
    const gchar * message, GBytes * data);
G_GNUC_INTERNAL void _gum_script_core_post_message (GumScriptCore * self,
    const gchar * message);

G_GNUC_INTERNAL gchar * _gum_script_string_get (JSStringRef str);
G_GNUC_INTERNAL gchar * _gum_script_string_from_value (JSValueRef value,
    JSContextRef ctx);
G_GNUC_INTERNAL JSValueRef _gum_script_string_to_value (const gchar * str,
    JSContextRef ctx);

G_GNUC_INTERNAL JSValueRef _gum_script_object_get (JSObjectRef object,
    const gchar * key, JSContextRef ctx);
G_GNUC_INTERNAL guint _gum_script_object_get_uint (JSObjectRef object,
    const gchar * key, JSContextRef ctx);
G_GNUC_INTERNAL gchar * _gum_script_object_get_string (JSObjectRef object,
    const gchar * key, JSContextRef ctx);
G_GNUC_INTERNAL void _gum_script_object_set (JSObjectRef object,
    const gchar * key, JSValueRef value, JSContextRef ctx);
G_GNUC_INTERNAL void _gum_script_object_set_string (JSObjectRef object,
    const gchar * key, const gchar * value, JSContextRef ctx);
G_GNUC_INTERNAL void _gum_script_object_set_function (JSObjectRef object,
    const gchar * key, JSObjectCallAsFunctionCallback callback,
    JSContextRef ctx);

G_GNUC_INTERNAL GBytes * _gum_script_byte_array_get (JSValueRef value,
    JSContextRef ctx, JSValueRef * exception);
G_GNUC_INTERNAL GBytes * _gum_script_byte_array_try_get (JSValueRef value,
    JSContextRef ctx);

G_GNUC_INTERNAL void _gum_script_throw (JSValueRef * exception,
    JSContextRef ctx, const gchar * format, ...);
G_GNUC_INTERNAL void _gum_script_panic (JSValueRef exception, JSContextRef ctx);

#endif
