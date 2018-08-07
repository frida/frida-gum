/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8scope.h"

#include "gumv8script-priv.h"

using namespace v8;

ScriptScope::ScriptScope (GumV8Script * parent)
  : parent (parent),
    stalker_scope (parent),
    locker (parent->isolate),
    isolate_scope (parent->isolate),
    handle_scope (parent->isolate),
    context (Local<Context>::New (parent->isolate, *parent->context)),
    context_scope (context),
    trycatch (parent->isolate),
    interceptor_scope (parent)
{
  auto core = &parent->core;

  _gum_v8_core_pin (core);

  next = core->current_scope;
  core->current_scope = this;

  g_queue_init (&tick_callbacks);
  g_queue_init (&scheduled_sources);
}

ScriptScope::~ScriptScope ()
{
  auto core = &parent->core;

  ProcessAnyPendingException ();

  PerformPendingIO ();

  core->current_scope = next;

  _gum_v8_core_unpin (core);

  auto pending_flush_notify = core->flush_notify;
  if (pending_flush_notify != NULL && core->usage_count == 0)
  {
    core->flush_notify = NULL;

    auto isolate = parent->isolate;
    isolate->Exit ();
    {
      Unlocker ul (isolate);

      _gum_v8_core_notify_flushed (core, pending_flush_notify);
    }
    isolate->Enter ();
  }
}

void
ScriptScope::ProcessAnyPendingException ()
{
  if (trycatch.HasCaught ())
  {
    auto exception = trycatch.Exception ();
    trycatch.Reset ();
    _gum_v8_core_on_unhandled_exception (&parent->core, exception);
    trycatch.Reset ();
  }
}

void
ScriptScope::PerformPendingIO ()
{
  auto core = &parent->core;

  if (!g_queue_is_empty (&tick_callbacks))
  {
    auto isolate = parent->isolate;

    GumPersistent<Function>::type * tick_callback;
    auto receiver = Undefined (isolate);
    while ((tick_callback = (GumPersistent<Function>::type *)
        g_queue_pop_head (&tick_callbacks)) != nullptr)
    {
      auto callback = Local<Function>::New (isolate, *tick_callback);

      callback->Call (receiver, 0, nullptr);
      ProcessAnyPendingException ();

      delete tick_callback;
    }
  }

  GSource * source;
  while ((source = (GSource *) g_queue_pop_head (&scheduled_sources)) != NULL)
  {
    if (!g_source_is_destroyed (source))
    {
      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
    }

    g_source_unref (source);
  }
}

void
ScriptScope::AddTickCallback (Handle<Function> callback)
{
  g_queue_push_tail (&tick_callbacks, new GumPersistent<Function>::type (
      parent->isolate, callback));
}

void
ScriptScope::AddScheduledSource (GSource * source)
{
  g_queue_push_tail (&scheduled_sources, source);
}

ScriptInterceptorScope::ScriptInterceptorScope (GumV8Script * parent)
  : parent (parent)
{
  gum_interceptor_begin_transaction (parent->interceptor.interceptor);
}

ScriptInterceptorScope::~ScriptInterceptorScope ()
{
  gum_interceptor_end_transaction (parent->interceptor.interceptor);
}

ScriptStalkerScope::ScriptStalkerScope (GumV8Script * parent)
  : pending_level (0),
    transformer (NULL),
    sink (NULL),
    parent (parent)
{
}

ScriptStalkerScope::~ScriptStalkerScope ()
{
  _gum_v8_stalker_process_pending (&parent->stalker, this);
}
