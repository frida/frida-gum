/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptcore.h"

void
_gum_script_core_init (GumScriptCore * self,
                       GumScript * script,
                       GumScriptCoreMessageEmitter message_emitter,
                       GumScriptScheduler * scheduler,
                       JSContextRef context,
                       JSObjectRef scope)
{
  JSObjectRef placeholder;

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->context = context;

  placeholder = JSObjectMake (context, NULL, NULL);

  _gum_script_object_set (scope, "global", scope, context);

  _gum_script_object_set (scope, "Kernel", placeholder, context);
  _gum_script_object_set (scope, "Memory", placeholder, context);
  _gum_script_object_set (scope, "NativePointer", placeholder, context);
}

void
_gum_script_core_realize (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_flush (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  g_object_unref (self->exceptor);
  self->exceptor = NULL;
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  (void) self;
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               GBytes * data)
{
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
}

gchar *
_gum_script_string_get (JSStringRef str)
{
  gsize size;
  gchar * result;

  size = JSStringGetMaximumUTF8CStringSize (str);
  result = g_malloc (size);
  JSStringGetUTF8CString (str, result, size);

  return result;
}

guint
_gum_script_object_get_uint (JSObjectRef object,
                             const gchar * key,
                             JSContextRef context)
{
  JSStringRef property;
  JSValueRef value;

  property = JSStringCreateWithUTF8CString (key);
  value = JSObjectGetProperty (context, object, property, NULL);
  g_assert (value != NULL);
  g_assert (JSValueIsNumber (context, value));
  JSStringRelease (property);

  return (guint) JSValueToNumber (context, value, NULL);
}

gchar *
_gum_script_object_get_string (JSObjectRef object,
                               const gchar * key,
                               JSContextRef context)
{
  gchar * result;
  JSStringRef property;
  JSValueRef value;
  JSStringRef str;

  property = JSStringCreateWithUTF8CString (key);
  value = JSObjectGetProperty (context, object, property, NULL);
  g_assert (value != NULL);
  g_assert (JSValueIsString (context, value));
  JSStringRelease (property);

  str = JSValueToStringCopy (context, value, NULL);
  result = _gum_script_string_get (str);
  JSStringRelease (str);

  return result;
}

void
_gum_script_object_set (JSObjectRef object,
                        const gchar * key,
                        JSValueRef value,
                        JSContextRef context)
{
  JSStringRef property;

  property = JSStringCreateWithUTF8CString (key);
  JSObjectSetProperty (context, object, property, value,
      kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete, NULL);
  JSStringRelease (property);
}

void
_gum_script_panic (JSValueRef exception,
                   JSContextRef context)
{
  JSStringRef message;
  gchar * message_str, * stack;

  message = JSValueToStringCopy (context, exception, NULL);
  message_str = _gum_script_string_get (message);
  stack = _gum_script_object_get_string ((JSObjectRef) exception, "stack",
      context);
  g_critical ("%s\n%s", message_str, stack);
  g_free (stack);
  g_free (message_str);
  JSStringRelease (message);

  abort ();
}
