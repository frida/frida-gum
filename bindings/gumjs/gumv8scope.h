/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SCOPE_H__
#define __GUM_V8_SCOPE_H__

#include "gumv8script.h"

#include <v8.h>

class ScriptInterceptorScope
{
public:
  ScriptInterceptorScope (GumV8Script * parent);
  ~ScriptInterceptorScope ();

private:
  GumV8Script * parent;
};

class ScriptStalkerScope
{
public:
  ScriptStalkerScope (GumV8Script * parent);
  ~ScriptStalkerScope ();

private:
  GumV8Script * parent;
};

class ScriptScope
{
public:
  ScriptScope (GumV8Script * parent);
  ~ScriptScope ();

  bool HasPendingException () const { return trycatch.HasCaught (); }
  void PerformPendingIO ();

  void AddTickCallback (v8::Handle<v8::Function> callback);
  void AddScheduledSource (GSource * source);

private:
  GumV8Script * parent;
  ScriptStalkerScope stalker_scope;
  v8::Locker locker;
  v8::Isolate::Scope isolate_scope;
  v8::HandleScope handle_scope;
  v8::Local<v8::Context> context;
  v8::Context::Scope context_scope;
  v8::TryCatch trycatch;
  ScriptInterceptorScope interceptor_scope;
  ScriptScope * next;
  GQueue tick_callbacks;
  GQueue scheduled_sources;
};

#endif
