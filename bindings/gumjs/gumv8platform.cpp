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
public:
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

template<class T>
class GumV8TaskRequest
{
public:
  GumV8TaskRequest (Platform * platform,
                    Isolate * isolate,
                    T * task)
    : platform(platform),
      isolate(isolate),
      task(task)
  {
  }

  ~GumV8TaskRequest ()
  {
    delete task;
  }

  Platform * platform;
  Isolate * isolate;
  T * task;
};

GumV8Platform::GumV8Platform ()
  : disposing (false),
    scheduler (gum_script_scheduler_new ()),
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
  disposing = true;

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

size_t
GumV8Platform::NumberOfAvailableBackgroundThreads ()
{
  return g_get_num_processors ();
}

void
GumV8Platform::CallOnBackgroundThread (Task * task,
                                       ExpectedRuntime expected_runtime)
{
  (void) expected_runtime;

  if (disposing)
  {
    /* This happens during V8::Dispose() */
    task->Run ();
    delete task;
    return;
  }

  GumV8TaskRequest<Task> * request =
      new GumV8TaskRequest<Task> (this, nullptr, task);

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      (GumScriptJobFunc) HandleTaskRequest, request, NULL);
}

void
GumV8Platform::CallOnForegroundThread (Isolate * for_isolate,
                                       Task * task)
{
  g_assert (!disposing);

  GumV8TaskRequest<Task> * request =
      new GumV8TaskRequest<Task> (this, for_isolate, task);

  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) HandleTaskRequest, request, NULL);
}

void
GumV8Platform::CallDelayedOnForegroundThread (Isolate * for_isolate,
                                              Task * task,
                                              double delay_in_seconds)
{
  g_assert (!disposing);

  GumV8TaskRequest<Task> * request =
      new GumV8TaskRequest<Task> (this, for_isolate, task);

  GSource * source = g_timeout_source_new (delay_in_seconds * 1000.0);
  g_source_set_priority (source, G_PRIORITY_DEFAULT);
  g_source_set_callback (source, (GSourceFunc) HandleDelayedTaskRequest,
      request, NULL);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));
  g_source_unref (source);
}

void
GumV8Platform::CallIdleOnForegroundThread (Isolate * for_isolate,
                                           IdleTask * task)
{
  g_assert (!disposing);

  GumV8TaskRequest<IdleTask> * request =
      new GumV8TaskRequest<IdleTask> (this, for_isolate, task);

  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) HandleIdleTaskRequest, request, NULL);
}

bool
GumV8Platform::IdleTasksEnabled (Isolate * for_isolate)
{
  (void) for_isolate;

  return true;
}

double
GumV8Platform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;
  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

void
GumV8Platform::HandleTaskRequest (GumV8TaskRequest<Task> * request)
{
  Isolate * isolate = request->isolate;

  if (isolate != nullptr)
  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    request->task->Run ();

    delete request;
  }
  else
  {
    request->task->Run ();

    delete request;
  }
}

gboolean
GumV8Platform::HandleDelayedTaskRequest (GumV8TaskRequest<Task> * request)
{
  HandleTaskRequest (request);

  return FALSE;
}

void
GumV8Platform::HandleIdleTaskRequest (GumV8TaskRequest<IdleTask> * request)
{
  Isolate * isolate = request->isolate;

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  const double deadline_in_seconds =
      request->platform->MonotonicallyIncreasingTime () + (1.0 / 60.0);
  request->task->Run (deadline_in_seconds);

  delete request;
}
