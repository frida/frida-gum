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

#include <gum/gumcloak.h>
#include <gum/gummemory.h>

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

  void
  Await ()
  {
    g_mutex_lock (&platform->lock);
    while (!completed)
      g_cond_wait (&cond, &platform->lock);
    g_mutex_unlock (&platform->lock);
  }

  void
  Complete ()
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

  virtual ~GumV8TaskRequest () = default;

  void
  ClearIsolate ()
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

  void
  Perform ()
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

  void
  Perform ()
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
  void
  RunTask ()
  {
    const double deadline_in_seconds =
        platform->MonotonicallyIncreasingTime () + (1.0 / 60.0);
    task->Run (deadline_in_seconds);
  }

  IdleTask * task;
};

class GumMemoryBackend : public MemoryBackend
{
public:
  void *
  Allocate (const size_t size,
            bool is_executable,
            void * hint) override
  {
    gpointer base = gum_memory_allocate (size,
        is_executable ? GUM_PAGE_RWX : GUM_PAGE_RW, hint);
    if (base != NULL)
      Cloak (base, size);
    return base;
  }

  void *
  Reserve (size_t size,
           void * hint) override
  {
    gpointer base = gum_memory_reserve (size, hint);
    if (base != NULL)
      Cloak (base, size);
    return base;
  }

  bool
  Commit (void * base,
          size_t size,
          bool is_executable) override
  {
    return !!gum_memory_commit (base, size,
        is_executable ? GUM_PAGE_RWX : GUM_PAGE_RW);
  }

  bool
  Uncommit (void * base,
            size_t size) override
  {
    return !!gum_memory_uncommit (base, size);
  }

  bool
  ReleasePartial (void * base,
                  size_t size,
                  void * free_start,
                  size_t free_size) override
  {
    bool success =
        !!gum_memory_release_partial (base, size, free_start, free_size);
    if (success)
      Uncloak (free_start, free_size);
    return success;
  }

  bool
  Release (void * base,
           size_t size) override
  {
    bool success = !!gum_memory_release (base, size);
    if (success)
      Uncloak (base, size);
    return success;
  }

private:
  void
  Cloak (gpointer base,
         gsize size)
  {
    GumMemoryRange r;
    r.base_address = GUM_ADDRESS (base);
    r.size = size;
    gum_cloak_add_range (&r);
  }

  void
  Uncloak (gpointer base,
           gsize size)
  {
    GumMemoryRange r;
    r.base_address = GUM_ADDRESS (base);
    r.size = size;
    gum_cloak_remove_range (&r);
  }
};

class GumMutex : public MutexImpl
{
public:
  GumMutex ()
  {
    g_mutex_init (&mutex);
  }

  ~GumMutex () override
  {
    g_mutex_clear (&mutex);
  }

  void
  Lock () override
  {
    g_mutex_lock (&mutex);
  }

  void
  Unlock () override
  {
    g_mutex_unlock (&mutex);
  }

  bool
  TryLock () override
  {
    return !!g_mutex_trylock (&mutex);
  }

private:
  GMutex mutex;

  friend class GumConditionVariable;
};

class GumRecursiveMutex : public MutexImpl
{
public:
  GumRecursiveMutex ()
  {
    g_rec_mutex_init (&mutex);
  }

  ~GumRecursiveMutex () override
  {
    g_rec_mutex_clear (&mutex);
  }

  void
  Lock () override
  {
    g_rec_mutex_lock (&mutex);
  }

  void
  Unlock () override
  {
    g_rec_mutex_unlock (&mutex);
  }

  bool
  TryLock () override
  {
    return !!g_rec_mutex_trylock (&mutex);
  }

private:
  GRecMutex mutex;
};

class GumConditionVariable : public ConditionVariableImpl
{
public:
  GumConditionVariable ()
  {
    g_cond_init (&cond);
  }

  ~GumConditionVariable () override
  {
    g_cond_clear (&cond);
  }

  void
  NotifyOne () override
  {
    g_cond_signal (&cond);
  }

  void
  NotifyAll () override
  {
    g_cond_broadcast (&cond);
  }

  void
  Wait (MutexImpl * mutex) override
  {
    GumMutex * m = (GumMutex *) mutex;
    g_cond_wait (&cond, &m->mutex);
  }

  bool
  WaitFor (MutexImpl * mutex,
           int64_t delta_in_microseconds) override
  {
    GumMutex * m = (GumMutex *) mutex;
    gint64 deadline = g_get_monotonic_time () + delta_in_microseconds;
    return !!g_cond_wait_until (&cond, &m->mutex, deadline);
  }

private:
  GCond cond;
};

class GumThreadingBackend : public ThreadingBackend
{
public:
  MutexImpl *
  CreatePlainMutex () override
  {
    return new GumMutex ();
  }

  MutexImpl *
  CreateRecursiveMutex () override
  {
    return new GumRecursiveMutex ();
  }

  ConditionVariableImpl *
  CreateConditionVariable () override
  {
    return new GumConditionVariable ();
  }
};

class GumArrayBufferAllocator : public ArrayBuffer::Allocator
{
public:
  void *
  Allocate (size_t length) override
  {
    return g_malloc0 (length);
  }

  void *
  AllocateUninitialized (size_t length) override
  {
    return g_malloc (length);
  }

  void
  Free (void * data,
        size_t length) override
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
    memory_backend (new GumMemoryBackend ()),
    threading_backend (new GumThreadingBackend ()),
    tracing_controller (new TracingController ()),
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

  delete tracing_controller;
  delete threading_backend;
  delete memory_backend;
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

MemoryBackend *
GumV8Platform::GetMemoryBackend ()
{
  return memory_backend;
}

ThreadingBackend *
GumV8Platform::GetThreadingBackend ()
{
  return threading_backend;
}

TracingController *
GumV8Platform::GetTracingController ()
{
  return tracing_controller;
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
