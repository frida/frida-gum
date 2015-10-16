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
                       JSContextRef context)
{
  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->context = context;
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
_gum_script_object_get_uint (JSObjectRef obj,
                             const gchar * key,
                             JSContextRef context)
{
  JSStringRef property;
  JSValueRef value;

  property = JSStringCreateWithUTF8CString (key);
  value = JSObjectGetProperty (context, obj, property, NULL);
  JSStringRelease (property);

  return (guint) JSValueToNumber (context, value, NULL);
}

void
_gum_script_panic (JSValueRef exception,
                   JSContextRef context)
{
  JSStringRef message;
  gchar * message_str;

  message = JSValueToStringCopy (context, exception, NULL);
  message_str = _gum_script_string_get (message);
  g_critical ("%s", message_str);
  g_free (message_str);
  JSStringRelease (message);

  abort ();
}
