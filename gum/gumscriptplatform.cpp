/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptplatform.h"

#include <v8.h>

using namespace v8;

GumScriptPlatform::GumScriptPlatform ()
  : scheduler (gum_script_scheduler_new ()),
    start_time (g_get_monotonic_time ())
{
  V8::InitializePlatform (this);
  V8::Initialize ();

  isolate = Isolate::New ();

  InitRuntime ();
}

void
GumScriptPlatform::InitRuntime ()
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  Local<Context> context (Context::New (isolate));
  Context::Scope context_scope (context);

  Local<String> resource_name (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> ("frida.js"),
      NewStringType::kNormal).ToLocalChecked ());
  ScriptOrigin origin (resource_name);

  gchar * c_string = g_strconcat (
#include "gumscript-runtime.h"
      (gpointer) NULL);
  Local<String> source_string (String::NewFromUtf8 (isolate, c_string));
  g_free (c_string);
  ScriptCompiler::Source source (source_string, origin);

  runtime.Reset (isolate, ScriptCompiler::CompileUnboundScript (isolate,
      &source).ToLocalChecked ());
}

GumScriptPlatform::~GumScriptPlatform ()
{
  isolate->Dispose ();

  V8::Dispose ();
  V8::ShutdownPlatform ();

  g_object_unref (scheduler);
}

Isolate *
GumScriptPlatform::GetIsolate () const
{
  return isolate;
}

Local<UnboundScript>
GumScriptPlatform::GetRuntime () const
{
  return v8::Local<v8::UnboundScript>::New (isolate, runtime);
}

GumScriptScheduler *
GumScriptPlatform::GetScheduler () const
{
  return scheduler;
}

void
GumScriptPlatform::CallOnBackgroundThread (Task * task,
                                           ExpectedRuntime expected_runtime)
{
  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask, NULL);
}

void
GumScriptPlatform::CallOnForegroundThread (Isolate * isolate,
                                           Task * task)
{
  gum_script_scheduler_push_job_on_v8_thread (scheduler, G_PRIORITY_HIGH,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask, NULL);
}

double
GumScriptPlatform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;
  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

void
GumScriptPlatform::PerformTask (Task * task)
{
  task->Run ();
}

void
GumScriptPlatform::DisposeTask (Task * task)
{
  delete task;
}

