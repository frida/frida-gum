/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptscope.h"

#include "gumscript-priv.h"

using namespace v8;

ScriptScope::ScriptScope (GumScript * parent)
  : parent (parent),
    stalker_scope (parent),
    locker (parent->priv->isolate),
    isolate_scope (parent->priv->isolate),
    handle_scope (parent->priv->isolate),
    context (Local<Context>::New (parent->priv->isolate, *parent->priv->context)),
    context_scope (context),
    trycatch (parent->priv->isolate)
{
}

ScriptScope::~ScriptScope ()
{
  GumScriptPrivate * priv = parent->priv;

  if (trycatch.HasCaught ())
  {
    Handle<Message> message = trycatch.Message ();
    Handle<Value> exception = trycatch.Exception ();
    trycatch.Reset ();

    GString * error = g_string_new ("{\"type\":\"error\"");

    Local<Value> resource_name = message->GetScriptResourceName ();
    if (!resource_name->IsUndefined ())
    {
      String::Utf8Value resource_name_str (resource_name->ToString ());
      g_string_append_printf (error, ",\"fileName\":\"%s\"",
          *resource_name_str);

      Maybe<int> line_number = message->GetLineNumber (context);
      if (line_number.IsJust ())
      {
        g_string_append_printf (error, ",\"lineNumber\":%d",
            line_number.FromJust ());
      }
    }

    String::Utf8Value exception_str (exception);
    gchar * exception_str_escaped = g_strescape (*exception_str, "");
    g_string_append_printf (error, ",\"description\":\"%s\"",
        exception_str_escaped);
    g_free (exception_str_escaped);

    g_string_append_c (error, '}');

    _gum_script_core_emit_message (&priv->core, error->str, NULL, 0);

    g_string_free (error, TRUE);
  }
}

ScriptStalkerScope::ScriptStalkerScope (GumScript * parent)
  : parent (parent)
{
}

ScriptStalkerScope::~ScriptStalkerScope ()
{
  _gum_script_stalker_process_pending (&parent->priv->stalker);
}

