/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8scope.h"

#include "gumv8script-priv.h"

using namespace v8;

ScriptScope::ScriptScope (GumV8Script * parent)
  : parent (parent),
    interceptor_scope (parent),
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
  GumV8ScriptPrivate * priv = parent->priv;

  if (trycatch.HasCaught ())
  {
    Handle<Value> exception = trycatch.Exception ();
    trycatch.Reset ();
    _gum_v8_core_on_unhandled_exception (&priv->core, exception);
    trycatch.Reset ();
  }
}

ScriptInterceptorScope::ScriptInterceptorScope (GumV8Script * parent)
  : parent (parent)
{
  gum_interceptor_begin_transaction (parent->priv->interceptor.interceptor);
}

ScriptInterceptorScope::~ScriptInterceptorScope ()
{
  gum_interceptor_end_transaction (parent->priv->interceptor.interceptor);
}

ScriptStalkerScope::ScriptStalkerScope (GumV8Script * parent)
  : parent (parent)
{
}

ScriptStalkerScope::~ScriptStalkerScope ()
{
  _gum_v8_stalker_process_pending (&parent->priv->stalker);
}

