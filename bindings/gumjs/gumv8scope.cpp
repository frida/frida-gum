/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
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

  next_scope = core->current_scope;
  next_owner = core->current_owner;
  core->current_scope = this;
  core->current_owner = gum_process_get_current_thread_id ();

  root_scope = this;
  while (root_scope->next_scope != nullptr)
    root_scope = root_scope->next_scope;

  tick_callbacks = &root_scope->tick_callbacks_storage;
  scheduled_sources = &root_scope->scheduled_sources_storage;

  if (this == root_scope)
  {
    g_queue_init (&tick_callbacks_storage);
    g_queue_init (&scheduled_sources_storage);
  }
}

ScriptScope::~ScriptScope ()
{
  auto core = &parent->core;

  ProcessAnyPendingException ();

  if (this == root_scope)
    PerformPendingIO ();

  core->current_scope = next_scope;
  core->current_owner = next_owner;

  _gum_v8_core_unpin (core);

  auto pending_flush_notify = core->flush_notify;
  if (pending_flush_notify != NULL && core->usage_count == 0)
  {
    core->flush_notify = NULL;

    {
      ScriptUnlocker unlocker (core);

      _gum_v8_core_notify_flushed (core, pending_flush_notify);
    }
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
  auto isolate = parent->isolate;

  bool io_performed;
  do
  {
    io_performed = false;

    isolate->PerformMicrotaskCheckpoint ();

    if (!g_queue_is_empty (tick_callbacks))
    {
      GumPersistent<Function>::type * tick_callback;
      auto receiver = Undefined (isolate);
      while ((tick_callback = (GumPersistent<Function>::type *)
          g_queue_pop_head (tick_callbacks)) != nullptr)
      {
        auto callback = Local<Function>::New (isolate, *tick_callback);

        auto result = callback->Call (context, receiver, 0, nullptr);
        if (result.IsEmpty ())
          ProcessAnyPendingException ();

        delete tick_callback;
      }

      io_performed = true;
    }

    GSource * source;
    while ((source = (GSource *) g_queue_pop_head (scheduled_sources)) != NULL)
    {
      if (!g_source_is_destroyed (source))
      {
        g_source_attach (source,
            gum_script_scheduler_get_js_context (core->scheduler));
      }

      g_source_unref (source);

      io_performed = true;
    }
  }
  while (io_performed);
}

void
ScriptScope::AddTickCallback (Local<Function> callback)
{
  g_queue_push_tail (tick_callbacks, new GumPersistent<Function>::type (
      parent->isolate, callback));
}

void
ScriptScope::AddScheduledSource (GSource * source)
{
  g_queue_push_tail (scheduled_sources, source);
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

ScriptUnlocker::ScriptUnlocker (GumV8Core * core)
  : exit_interceptor_scope (core),
    exit_current_scope (core),
    exit_isolate_scope (core->isolate),
    unlocker (core->isolate)
{
}

ScriptUnlocker::ExitInterceptorScope::ExitInterceptorScope (
    GumV8Core * core)
  : interceptor (core->script->interceptor.interceptor)
{
  gum_interceptor_end_transaction (interceptor);
}

ScriptUnlocker::ExitInterceptorScope::~ExitInterceptorScope ()
{
  gum_interceptor_begin_transaction (interceptor);
}

ScriptUnlocker::ExitCurrentScope::ExitCurrentScope (GumV8Core * core)
  : core (core),
    scope (core->current_scope),
    owner (core->current_owner)
{
  core->current_scope = nullptr;
  core->current_owner = GUM_THREAD_ID_INVALID;
}

ScriptUnlocker::ExitCurrentScope::~ExitCurrentScope ()
{
  core->current_scope = scope;
  core->current_owner = owner;
}

ScriptUnlocker::ExitIsolateScope::ExitIsolateScope (Isolate * isolate)
  : isolate (isolate)
{
  isolate->Exit ();
}

ScriptUnlocker::ExitIsolateScope::~ExitIsolateScope ()
{
  isolate->Enter ();
}
