/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8platform.h"

#include "gumv8script-debug.h"
#include "gumv8script-java.h"
#include "gumv8script-objc.h"
#include "gumv8script-runtime.h"

using namespace v8;

class GumV8DisposeRequest
{
public:
  GumV8DisposeRequest (GumV8Platform * platform)
    : platform (platform),
      completed (false)
  {
    g_cond_init (&cond);
  }

  ~GumV8DisposeRequest ()
  {
    g_cond_clear (&cond);
  }

  void Await ()
  {
    g_mutex_lock (&platform->lock);
    while (!completed)
      g_cond_wait (&cond, &platform->lock);
    g_mutex_unlock (&platform->lock);
  }

  void Complete ()
  {
    g_mutex_lock (&platform->lock);
    completed = true;
    g_cond_signal (&cond);
    g_mutex_unlock (&platform->lock);
  }

private:
  GumV8Platform * platform;
  GCond cond;
  bool completed;

  friend class GumV8Platform;
};

class GumV8TaskRequest
{
public:
  GumV8TaskRequest (GumV8Platform * platform,
                    Isolate * isolate)
    : platform(platform),
      isolate(isolate)
  {
  }

  virtual ~GumV8TaskRequest ()
  {
  }

  void ClearIsolate ()
  {
    isolate = nullptr;
  }

  virtual void Perform () = 0;

protected:
  GumV8Platform * platform;
  Isolate * isolate;

  friend class GumV8Platform;
};

class GumV8PlainTaskRequest : public GumV8TaskRequest
{
public:
  GumV8PlainTaskRequest (GumV8Platform * platform,
                         Isolate * isolate,
                         Task * task)
    : GumV8TaskRequest (platform, isolate),
      task (task)
  {
  }

  ~GumV8PlainTaskRequest ()
  {
    delete task;
  }

  void Perform ()
  {
    if (isolate != nullptr)
    {
      Locker locker (isolate);
      Isolate::Scope isolate_scope (isolate);
      HandleScope handle_scope (isolate);

      task->Run ();
    }
    else
    {
      task->Run ();
    }
  }

private:
  Task * task;
};

class GumV8IdleTaskRequest : public GumV8TaskRequest
{
public:
  GumV8IdleTaskRequest (GumV8Platform * platform,
                        Isolate * isolate,
                        IdleTask * task)
    : GumV8TaskRequest (platform, isolate),
      task (task)
  {
  }

  ~GumV8IdleTaskRequest ()
  {
    delete task;
  }

  void Perform ()
  {
    if (isolate != nullptr)
    {
      Locker locker (isolate);
      Isolate::Scope isolate_scope (isolate);
      HandleScope handle_scope (isolate);

      RunTask ();
    }
    else
    {
      RunTask ();
    }
  }

private:
  void RunTask ()
  {
    const double deadline_in_seconds =
        platform->MonotonicallyIncreasingTime () + (1.0 / 60.0);
    task->Run (deadline_in_seconds);
  }

  IdleTask * task;
};

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

GumV8Platform::GumV8Platform ()
  : objc_bundle (NULL),
    java_bundle (NULL),
    scheduler (gum_script_scheduler_new ()),
    start_time (g_get_monotonic_time ()),
    array_buffer_allocator (new GumArrayBufferAllocator ()),
    pending_foreground_tasks (g_hash_table_new (NULL, NULL))
{
  g_mutex_init (&lock);

  V8::InitializePlatform (this);
  V8::Initialize ();

  Isolate::CreateParams params;
  params.array_buffer_allocator = array_buffer_allocator;

  isolate = Isolate::New (params);
  isolate->SetFatalErrorHandler (OnFatalError);

  InitRuntime ();
}

GumV8Platform::~GumV8Platform ()
{
  GumV8DisposeRequest request (this);
  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_HIGH,
      (GumScriptJobFunc) PerformDispose, &request, NULL);
  request.Await ();

  g_hash_table_unref (pending_foreground_tasks);

  g_object_unref (scheduler);

  delete array_buffer_allocator;

  g_mutex_clear (&lock);
}

void
GumV8Platform::InitRuntime ()
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  Local<Context> context (Context::New (isolate));
  Context::Scope context_scope (context);

  runtime_bundle = gum_v8_bundle_new (isolate, gumjs_runtime_modules);
  debug_bundle = gum_v8_bundle_new (isolate, gumjs_debug_modules);
}

void
GumV8Platform::PerformDispose (GumV8DisposeRequest * dispose_request)
{
  dispose_request->platform->Dispose (dispose_request);
}

void
GumV8Platform::Dispose (GumV8DisposeRequest * dispose_request)
{
  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    g_clear_pointer (&objc_bundle, gum_v8_bundle_free);
    g_clear_pointer (&java_bundle, gum_v8_bundle_free);

    g_clear_pointer (&debug_bundle, gum_v8_bundle_free);
    g_clear_pointer (&runtime_bundle, gum_v8_bundle_free);
  }

  isolate->Dispose ();

  g_mutex_lock (&lock);

  while (g_hash_table_size (pending_foreground_tasks) > 0)
  {
    GHashTableIter iter;
    GumV8TaskRequest * request;
    GSource * source;

    g_hash_table_iter_init (&iter, pending_foreground_tasks);
    g_hash_table_iter_next (&iter, (gpointer *) &request, (gpointer *) &source);
    g_hash_table_iter_remove (&iter);

    g_mutex_unlock (&lock);

    g_source_destroy (source);

    request->ClearIsolate ();
    request->Perform ();
    delete request;

    g_mutex_lock (&lock);
  }

  g_mutex_unlock (&lock);

  V8::Dispose ();
  V8::ShutdownPlatform ();

  dispose_request->Complete ();
}

void
GumV8Platform::OnFatalError (const char * location,
                             const char * message)
{
  g_log ("V8", G_LOG_LEVEL_ERROR, "%s: %s", location, message);
}

const gchar *
GumV8Platform::GetRuntimeSourceMap () const
{
  return gumjs_frida_source_map;
}

GumV8Bundle *
GumV8Platform::GetObjCBundle ()
{
  if (objc_bundle == NULL)
    objc_bundle = gum_v8_bundle_new (isolate, gumjs_objc_modules);
  return objc_bundle;
}

const gchar *
GumV8Platform::GetObjCSourceMap () const
{
  return gumjs_objc_source_map;
}

GumV8Bundle *
GumV8Platform::GetJavaBundle ()
{
  if (java_bundle == NULL)
    java_bundle = gum_v8_bundle_new (isolate, gumjs_java_modules);
  return java_bundle;
}

const gchar *
GumV8Platform::GetJavaSourceMap () const
{
  return gumjs_java_source_map;
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

  auto request = new GumV8PlainTaskRequest (this, nullptr, task);

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      (GumScriptJobFunc) HandleBackgroundTaskRequest, request, NULL);
}

void
GumV8Platform::CallOnForegroundThread (Isolate * for_isolate,
                                       Task * task)
{
  auto request = new GumV8PlainTaskRequest (this, for_isolate, task);

  auto source = g_idle_source_new ();
  g_source_set_priority (source, G_PRIORITY_DEFAULT);
  ScheduleForegroundTask (request, source);
}

void
GumV8Platform::CallDelayedOnForegroundThread (Isolate * for_isolate,
                                              Task * task,
                                              double delay_in_seconds)
{
  auto request = new GumV8PlainTaskRequest (this, for_isolate, task);

  auto source = g_timeout_source_new (delay_in_seconds * 1000.0);
  g_source_set_priority (source, G_PRIORITY_LOW);
  ScheduleForegroundTask (request, source);
}

void
GumV8Platform::CallIdleOnForegroundThread (Isolate * for_isolate,
                                           IdleTask * task)
{
  auto request = new GumV8IdleTaskRequest (this, for_isolate, task);

  auto source = g_idle_source_new ();
  g_source_set_priority (source, G_PRIORITY_LOW);
  ScheduleForegroundTask (request, source);
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
GumV8Platform::HandleBackgroundTaskRequest (GumV8TaskRequest * request)
{
  request->Perform ();
  delete request;
}

gboolean
GumV8Platform::HandleForegroundTaskRequest (GumV8TaskRequest * request)
{
  request->Perform ();

  request->platform->OnForegroundTaskPerformed (request);

  delete request;

  return FALSE;
}

void
GumV8Platform::ScheduleForegroundTask (GumV8TaskRequest * request,
                                       GSource * source)
{
  g_source_set_callback (source, (GSourceFunc) HandleForegroundTaskRequest,
      request, NULL);

  g_mutex_lock (&lock);
  g_hash_table_insert (pending_foreground_tasks, request, source);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));
  g_mutex_unlock (&lock);

  g_source_unref (source);
}

void
GumV8Platform::OnForegroundTaskPerformed (GumV8TaskRequest * request)
{
  g_mutex_lock (&lock);
  g_hash_table_remove (pending_foreground_tasks, request);
  g_mutex_unlock (&lock);
}
