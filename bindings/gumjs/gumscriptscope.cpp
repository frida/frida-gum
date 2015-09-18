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
    Handle<Value> exception = trycatch.Exception ();
    trycatch.Reset ();
    _gum_script_core_on_unhandled_exception (&priv->core, exception);
    trycatch.Reset ();
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

