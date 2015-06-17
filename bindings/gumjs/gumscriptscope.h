/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SCOPE_H__
#define __GUM_SCRIPT_SCOPE_H__

#include "gumscript.h"

#include <v8.h>

class ScriptStalkerScope
{
public:
  ScriptStalkerScope (GumScript * parent);
  ~ScriptStalkerScope ();

private:
  GumScript * parent;
};

class ScriptScope
{
public:
  ScriptScope (GumScript * parent);
  ~ScriptScope ();

  bool HasPendingException () const { return trycatch.HasCaught (); }

private:
  GumScript * parent;
  ScriptStalkerScope stalker_scope;
  v8::Locker locker;
  v8::Isolate::Scope isolate_scope;
  v8::HandleScope handle_scope;
  v8::Local<v8::Context> context;
  v8::Context::Scope context_scope;
  v8::TryCatch trycatch;
};

#endif
