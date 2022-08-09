/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_MATCH_CONTEXT_H__
#define __GUM_V8_MATCH_CONTEXT_H__

#include "gumv8script.h"

#include <v8.h>

template <typename T>
class GumV8MatchContext
{
public:
  GumV8MatchContext (v8::Isolate * isolate, T * parent)
    : isolate (isolate),
      context (isolate->GetCurrentContext ()),
      recv (Undefined (isolate)),
      parent (parent),
      has_pending_exception (FALSE)
  {
  }

  gboolean
  OnMatch (v8::Local<v8::Value> item)
  {
    gboolean proceed = TRUE;

    v8::Local<v8::Value> argv[] = { item };
    v8::Local<v8::Value> result;
    if (on_match->Call (context, recv, G_N_ELEMENTS (argv),
        argv).ToLocal (&result))
    {
      if (result->IsString ())
      {
        v8::String::Utf8Value str (isolate, result);
        proceed = strcmp (*str, "stop") != 0;
      }
    }
    else
    {
      has_pending_exception = TRUE;
      proceed = FALSE;
    }

    return proceed;
  }

  void
  OnComplete ()
  {
    if (has_pending_exception)
      return;

    auto result = on_complete->Call (context, recv, 0, nullptr);
    _gum_v8_ignore_result (result);
  }

  v8::Local<v8::Function> on_match;
  v8::Local<v8::Function> on_complete;

  v8::Isolate * isolate;
  v8::Local<v8::Context> context;
  v8::Local<v8::Value> recv;
  T * parent;

private:
  gboolean has_pending_exception;
};

#endif
