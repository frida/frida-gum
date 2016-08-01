/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8platform.h"

#include "gumv8script-debug.h"
#include "gumv8script-runtime.h"

using namespace v8;

class GumArrayBufferAllocator : public ArrayBuffer::Allocator
{
  virtual void *
  Allocate (size_t length)
  {
    return g_malloc0 (length);
  }

  virtual void *
  AllocateUninitialized (size_t length)
  {
    return g_malloc (length);
  }

  virtual void
  Free (void * data, size_t length)
  {
    (void) length;

    g_free (data);
  }
};

GumV8Platform::GumV8Platform ()
  : scheduler (gum_script_scheduler_new ()),
    start_time (g_get_monotonic_time ()),
    array_buffer_allocator (new GumArrayBufferAllocator ())
{
  V8::InitializePlatform (this);
  V8::Initialize ();

  Isolate::CreateParams params;
  params.array_buffer_allocator = array_buffer_allocator;

  isolate = Isolate::New (params);
  isolate->SetFatalErrorHandler (OnFatalError);

  InitRuntime ();
}

void
GumV8Platform::InitRuntime ()
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  Local<Context> context (Context::New (isolate));
  Context::Scope context_scope (context);

  user_runtime = gum_v8_bundle_new (isolate, gum_v8_script_runtime_sources);
  debug_runtime = gum_v8_bundle_new (isolate, gum_v8_script_debug_sources);
}

void
GumV8Platform::OnFatalError (const char * location,
                             const char * message)
{
  g_log ("V8", G_LOG_LEVEL_ERROR, "%s: %s", location, message);
}

GumV8Platform::~GumV8Platform ()
{
  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    gum_v8_bundle_free (debug_runtime);
    gum_v8_bundle_free (user_runtime);
  }

  isolate->Dispose ();

  V8::Dispose ();
  V8::ShutdownPlatform ();

  g_object_unref (scheduler);

  delete array_buffer_allocator;
}

void
GumV8Platform::CallOnBackgroundThread (Task * task,
                                       ExpectedRuntime expected_runtime)
{
  (void) expected_runtime;

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask);
}

void
GumV8Platform::CallOnForegroundThread (Isolate * with_isolate,
                                       Task * task)
{
  (void) with_isolate;

  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_HIGH,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask);
}

double
GumV8Platform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;
  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

void
GumV8Platform::PerformTask (Task * task)
{
  task->Run ();
}

void
GumV8Platform::DisposeTask (Task * task)
{
  delete task;
}

