/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8platform.h"

#include "gumv8script-java.h"
#include "gumv8script-objc.h"
#include "gumv8script-runtime.h"

#include <gum/gumcloak.h>
#include <gum/gumcodesegment.h>
#include <gum/gummemory.h>

using namespace v8;

static GumPageProtection gum_page_protection_from_v8 (
    PageAllocator::Permission permission);

class GumV8MainContextOperation : public GumV8Operation
{
public:
  GumV8MainContextOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source);
  ~GumV8MainContextOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ThreadPoolOperation : public GumV8Operation
{
public:
  GumV8ThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func);
  ~GumV8ThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8DelayedThreadPoolOperation : public GumV8Operation
{
public:
  GumV8DelayedThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source);
  ~GumV8DelayedThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ForegroundTaskRunner : public TaskRunner
{
public:
  GumV8ForegroundTaskRunner (GumV8Platform * platform, Isolate * isolate);
  ~GumV8ForegroundTaskRunner () override;

  void PostTask (std::unique_ptr<Task> task) override;
  void PostDelayedTask (std::unique_ptr<Task> task,
      double delay_in_seconds) override;
  void PostIdleTask (std::unique_ptr<IdleTask> task) override;
  bool IdleTasksEnabled () override;

private:
  void Run (Task * task);
  void Run (IdleTask * task);

  GumV8Platform * platform;
  Isolate * isolate;
  GHashTable * pending;
};

class GumV8PageAllocator : public PageAllocator
{
public:
  size_t AllocatePageSize () override;
  size_t CommitPageSize () override;
  void SetRandomMmapSeed (int64_t seed) override;
  void * GetRandomMmapAddr () override;
  void * AllocatePages (void * address, size_t length, size_t alignment,
      Permission permissions) override;
  bool FreePages (void * address, size_t length) override;
  bool ReleasePages (void * address, size_t length, size_t new_length) override;
  bool SetPermissions (void * address, size_t length,
      Permission permissions) override;
};

class GumV8ArrayBufferAllocator : public ArrayBuffer::Allocator
{
public:
  GumV8ArrayBufferAllocator () = default;

  void * Allocate (size_t length) override;
  void * AllocateUninitialized (size_t length) override;
  void Free (void * data, size_t length) override;
};

class GumV8ThreadingBackend : public ThreadingBackend
{
public:
  GumV8ThreadingBackend () = default;

  MutexImpl * CreatePlainMutex () override;
  MutexImpl * CreateRecursiveMutex () override;
  SharedMutexImpl * CreateSharedMutex () override;
  ConditionVariableImpl * CreateConditionVariable () override;
};

class GumMutex : public MutexImpl
{
public:
  GumMutex ();
  ~GumMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GMutex mutex;

  friend class GumConditionVariable;
};

class GumRecursiveMutex : public MutexImpl
{
public:
  GumRecursiveMutex ();
  ~GumRecursiveMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GRecMutex mutex;
};

class GumSharedMutex : public SharedMutexImpl
{
public:
  GumSharedMutex ();
  ~GumSharedMutex () override;

  void LockShared () override;
  void LockExclusive () override;
  void UnlockShared () override;
  void UnlockExclusive () override;
  bool TryLockShared () override;
  bool TryLockExclusive () override;

private:
  GRWLock lock;
};

class GumConditionVariable : public ConditionVariableImpl
{
public:
  GumConditionVariable ();
  ~GumConditionVariable () override;

  void NotifyOne () override;
  void NotifyAll () override;
  void Wait (MutexImpl * mutex) override;
  bool WaitFor (MutexImpl * mutex, int64_t delta_in_microseconds) override;

private:
  GCond cond;
};

class GumV8PlatformLocker
{
public:
  GumV8PlatformLocker (GumV8Platform * platform)
    : platform (platform)
  {
    g_mutex_lock (&platform->lock);
  }

  GumV8PlatformLocker (const GumV8PlatformLocker &) = delete;

  GumV8PlatformLocker & operator= (const GumV8PlatformLocker &) = delete;

  ~GumV8PlatformLocker ()
  {
    g_mutex_unlock (&platform->lock);
  }

private:
  GumV8Platform * platform;
};

class GumV8PlatformUnlocker
{
public:
  GumV8PlatformUnlocker (GumV8Platform * platform)
    : platform (platform)
  {
    g_mutex_unlock (&platform->lock);
  }

  GumV8PlatformUnlocker (const GumV8PlatformUnlocker &) = delete;

  GumV8PlatformUnlocker & operator= (const GumV8PlatformUnlocker &) = delete;

  ~GumV8PlatformUnlocker ()
  {
    g_mutex_lock (&platform->lock);
  }

private:
  GumV8Platform * platform;
};

GumV8Platform::GumV8Platform ()
  : objc_bundle (NULL),
    java_bundle (NULL),
    scheduler (gum_script_scheduler_new ()),
    start_time (g_get_monotonic_time ()),
    page_allocator (new GumV8PageAllocator ()),
    array_buffer_allocator (new GumV8ArrayBufferAllocator ()),
    threading_backend (new GumV8ThreadingBackend ()),
    tracing_controller (new TracingController ())
{
  g_mutex_init (&lock);

  V8::InitializePlatform (this);
  V8::Initialize ();

  Isolate::CreateParams params;
  params.array_buffer_allocator = array_buffer_allocator.get ();

  shared_isolate = Isolate::New (params);
  shared_isolate->SetFatalErrorHandler (OnFatalError);
  shared_isolate->SetMicrotasksPolicy (MicrotasksPolicy::kExplicit);

  InitRuntime ();
}

GumV8Platform::~GumV8Platform ()
{
  auto dispose = ScheduleOnJSThread (G_PRIORITY_HIGH, [=]() { Dispose (); });
  {
    GumV8PlatformLocker locker (this);
    js_ops.erase (dispose);
  }
  dispose->Await ();

  g_object_unref (scheduler);

  g_mutex_clear (&lock);
}

void
GumV8Platform::InitRuntime ()
{
  Locker locker (shared_isolate);
  Isolate::Scope isolate_scope (shared_isolate);
  HandleScope handle_scope (shared_isolate);
  Local<Context> context (Context::New (shared_isolate));
  Context::Scope context_scope (context);

  runtime_bundle = gum_v8_bundle_new (shared_isolate, gumjs_runtime_modules);
}

void
GumV8Platform::Dispose ()
{
  CancelPendingOperations ();

  {
    Locker locker (shared_isolate);
    Isolate::Scope isolate_scope (shared_isolate);
    HandleScope handle_scope (shared_isolate);

    g_clear_pointer (&objc_bundle, gum_v8_bundle_free);
    g_clear_pointer (&java_bundle, gum_v8_bundle_free);

    g_clear_pointer (&runtime_bundle, gum_v8_bundle_free);
  }

  shared_isolate->Dispose ();

  CancelPendingOperations ();

  V8::Dispose ();
  V8::ShutdownPlatform ();
}

void
GumV8Platform::CancelPendingOperations ()
{
  GMainContext * main_context = gum_script_scheduler_get_js_context (scheduler);

  while (true)
  {
    std::unordered_set<std::shared_ptr<GumV8Operation>> js_ops_copy;
    std::unordered_set<std::shared_ptr<GumV8Operation>> pool_ops_copy;
    {
      GumV8PlatformLocker locker (this);

      js_ops_copy = js_ops;
      pool_ops_copy = pool_ops;
    }

    for (const auto & op : js_ops_copy)
      op->Cancel ();

    for (const auto & op : pool_ops_copy)
      op->Cancel ();
    for (const auto & op : pool_ops_copy)
      op->Await ();

    GumV8PlatformLocker locker (this);
    if (js_ops.empty () && pool_ops.empty ())
      break;

    bool anything_pending = false;
    while (g_main_context_pending (main_context))
    {
      anything_pending = true;
      g_main_context_iteration (main_context, FALSE);
    }
    if (!anything_pending)
      g_thread_yield ();
  }
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
    objc_bundle = gum_v8_bundle_new (shared_isolate, gumjs_objc_modules);
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
    java_bundle = gum_v8_bundle_new (shared_isolate, gumjs_java_modules);
  return java_bundle;
}

const gchar *
GumV8Platform::GetJavaSourceMap () const
{
  return gumjs_java_source_map;
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, G_PRIORITY_DEFAULT, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (gint priority,
                                   std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, priority, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (delay_in_milliseconds, G_PRIORITY_DEFAULT,
      f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          gint priority,
                                          std::function<void ()> f)
{
  GSource * source = (delay_in_milliseconds != 0)
      ? g_timeout_source_new (delay_in_milliseconds)
      : g_idle_source_new ();
  g_source_set_priority (source, priority);

  auto op = std::make_shared<GumV8MainContextOperation> (this, f, source);

  {
    GumV8PlatformLocker locker (this);
    js_ops.insert (op);
  }

  g_source_set_callback (source, PerformMainContextOperation,
      new std::shared_ptr<GumV8MainContextOperation> (op),
      ReleaseMainContextOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPool (std::function<void ()> f)
{
  auto op = std::make_shared<GumV8ThreadPoolOperation> (this, f);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      PerformThreadPoolOperation,
      new std::shared_ptr<GumV8ThreadPoolOperation> (op),
      ReleaseThreadPoolOperation);

  return op;
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPoolDelayed (guint delay_in_milliseconds,
                                            std::function<void ()> f)
{
  GSource * source = g_timeout_source_new (delay_in_milliseconds);
  g_source_set_priority (source, G_PRIORITY_HIGH);

  auto op = std::make_shared<GumV8DelayedThreadPoolOperation> (this, f, source);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  g_source_set_callback (source, StartDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

gboolean
GumV8Platform::PerformMainContextOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8MainContextOperation> *) data;

  (*operation)->Perform ();

  return FALSE;
}

void
GumV8Platform::ReleaseMainContextOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8MainContextOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->js_ops.erase (op);
  }

  delete ptr;
}

void
GumV8Platform::PerformThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->pool_ops.erase (op);
  }

  delete ptr;
}

gboolean
GumV8Platform::StartDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;
  auto op = *ptr;

  gum_script_scheduler_push_job_on_thread_pool (op->platform->scheduler,
      PerformDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);

  return FALSE;
}

void
GumV8Platform::PerformDelayedThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    switch (op->state)
    {
      case GumV8DelayedThreadPoolOperation::kScheduled:
      case GumV8DelayedThreadPoolOperation::kRunning:
        break;
      case GumV8DelayedThreadPoolOperation::kCompleted:
      case GumV8DelayedThreadPoolOperation::kCanceling:
      case GumV8DelayedThreadPoolOperation::kCanceled:
        platform->pool_ops.erase (op);
        break;
    }
  }

  delete ptr;
}

PageAllocator *
GumV8Platform::GetPageAllocator ()
{
  return page_allocator.get ();
}

int
GumV8Platform::NumberOfWorkerThreads ()
{
  return g_get_num_processors ();
}

std::shared_ptr<TaskRunner>
GumV8Platform::GetForegroundTaskRunner (Isolate * isolate)
{
  auto runner = foreground_runners[isolate];
  if (!runner)
  {
    runner = std::make_shared<GumV8ForegroundTaskRunner> (this, isolate);
    foreground_runners[isolate] = runner;
  }

  return runner;
}

void
GumV8Platform::CallOnWorkerThread (std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPool ([=]() { t->Run (); });
}

void
GumV8Platform::CallDelayedOnWorkerThread (std::unique_ptr<Task> task,
                                          double delay_in_seconds)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPoolDelayed (delay_in_seconds * 1000.0, [=]()
      {
        t->Run ();
      });
}

void
GumV8Platform::CallOnForegroundThread (Isolate * isolate,
                                       Task * task)
{
  GetForegroundTaskRunner (isolate)->PostTask (std::unique_ptr<Task> (task));
}

void
GumV8Platform::CallDelayedOnForegroundThread (Isolate * isolate,
                                              Task * task,
                                              double delay_in_seconds)
{
  GetForegroundTaskRunner (isolate)->PostDelayedTask (
      std::unique_ptr<Task> (task), delay_in_seconds);
}

void
GumV8Platform::CallIdleOnForegroundThread (Isolate * isolate,
                                           IdleTask * task)
{
  GetForegroundTaskRunner (isolate)->PostIdleTask (
      std::unique_ptr<IdleTask> (task));
}

bool
GumV8Platform::IdleTasksEnabled (Isolate * isolate)
{
  return true;
}

double
GumV8Platform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;

  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

double
GumV8Platform::CurrentClockTimeMillis ()
{
  return (double) (g_get_real_time () / G_GINT64_CONSTANT (1000));
}

ThreadingBackend *
GumV8Platform::GetThreadingBackend ()
{
  return threading_backend.get ();
}

TracingController *
GumV8Platform::GetTracingController ()
{
  return tracing_controller.get ();
}

GumV8MainContextOperation::GumV8MainContextOperation (
    GumV8Platform * platform,
    std::function<void ()> func,
    GSource * source)
  : platform (platform),
    func (func),
    source (source),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8MainContextOperation::~GumV8MainContextOperation ()
{
  g_source_unref (source);
  g_cond_clear (&cond);
}

void
GumV8MainContextOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8MainContextOperation::Cancel ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kCanceling;
  }

  g_source_destroy (source);

  {
    GumV8PlatformLocker locker (platform);
    state = kCanceled;
    g_cond_signal (&cond);
  }
}

void
GumV8MainContextOperation::Await ()
{
  GumV8PlatformLocker locker (platform);
  while (state != kCompleted && state != kCanceled)
    g_cond_wait (&cond, &platform->lock);
}

GumV8ThreadPoolOperation::GumV8ThreadPoolOperation (
    GumV8Platform * platform,
    std::function<void ()> func)
  : platform (platform),
    func (func),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8ThreadPoolOperation::~GumV8ThreadPoolOperation ()
{
  g_cond_clear (&cond);
}

void
GumV8ThreadPoolOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8ThreadPoolOperation::Cancel ()
{
  GumV8PlatformLocker locker (platform);
  if (state != kScheduled)
    return;
  state = kCanceled;
  g_cond_signal (&cond);
}

void
GumV8ThreadPoolOperation::Await ()
{
  GumV8PlatformLocker locker (platform);
  while (state != kCompleted && state != kCanceled)
    g_cond_wait (&cond, &platform->lock);
}

GumV8DelayedThreadPoolOperation::GumV8DelayedThreadPoolOperation (
    GumV8Platform * platform,
    std::function<void ()> func,
    GSource * source)
  : platform (platform),
    func (func),
    source (source),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8DelayedThreadPoolOperation::~GumV8DelayedThreadPoolOperation ()
{
  g_source_unref (source);
  g_cond_clear (&cond);
}

void
GumV8DelayedThreadPoolOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8DelayedThreadPoolOperation::Cancel ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kCanceling;
  }

  g_source_destroy (source);

  {
    GumV8PlatformLocker locker (platform);
    state = kCanceled;
    g_cond_signal (&cond);
  }
}

void
GumV8DelayedThreadPoolOperation::Await ()
{
  GumV8PlatformLocker locker (platform);
  while (state != kCompleted && state != kCanceled)
    g_cond_wait (&cond, &platform->lock);
}

GumV8ForegroundTaskRunner::GumV8ForegroundTaskRunner (GumV8Platform * platform,
                                                      Isolate * isolate)
  : platform (platform),
    isolate (isolate),
    pending (g_hash_table_new (NULL, NULL))
{
}

GumV8ForegroundTaskRunner::~GumV8ForegroundTaskRunner ()
{
  g_hash_table_unref (pending);
}

void
GumV8ForegroundTaskRunner::PostTask (std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  platform->ScheduleOnJSThread ([=]()
      {
        Run (t.get ());
      });
}

void
GumV8ForegroundTaskRunner::PostDelayedTask (std::unique_ptr<Task> task,
                                            double delay_in_seconds)
{
  std::shared_ptr<Task> t (std::move (task));
  platform->ScheduleOnJSThreadDelayed (delay_in_seconds * 1000.0, [=]()
      {
        Run (t.get ());
      });
}

void
GumV8ForegroundTaskRunner::PostIdleTask (std::unique_ptr<IdleTask> task)
{
  std::shared_ptr<IdleTask> t (std::move (task));
  platform->ScheduleOnJSThread (G_PRIORITY_LOW, [=]()
      {
        Run (t.get ());
      });
}

bool
GumV8ForegroundTaskRunner::IdleTasksEnabled ()
{
  return true;
}

void
GumV8ForegroundTaskRunner::Run (Task * task)
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  task->Run ();
}

void
GumV8ForegroundTaskRunner::Run (IdleTask * task)
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  const double deadline_in_seconds =
      platform->MonotonicallyIncreasingTime () + (1.0 / 60.0);
  task->Run (deadline_in_seconds);
}

size_t
GumV8PageAllocator::AllocatePageSize ()
{
  return gum_query_page_size ();
}

size_t
GumV8PageAllocator::CommitPageSize ()
{
  return gum_query_page_size ();
}

void
GumV8PageAllocator::SetRandomMmapSeed (int64_t seed)
{
}

void *
GumV8PageAllocator::GetRandomMmapAddr ()
{
  return GSIZE_TO_POINTER (16384);
}

void *
GumV8PageAllocator::AllocatePages (void * address,
                                   size_t length,
                                   size_t alignment,
                                   Permission permissions)
{
  gsize page_size = gum_query_page_size ();

  gsize allocation_size = length + (alignment - page_size);
  allocation_size = GUM_ALIGN_SIZE (allocation_size, page_size);

  guint8 * base = (guint8 *) gum_memory_allocate (allocation_size,
      gum_page_protection_from_v8 (permissions), NULL);
  if (base == NULL)
    return NULL;

  guint8 * aligned_base = GUM_ALIGN_POINTER (guint8 *, base, alignment);

  if (aligned_base != base)
  {
    gsize prefix_size = aligned_base - base;
    gum_memory_release (base, prefix_size);
    allocation_size -= prefix_size;
  }

  if (allocation_size != length)
  {
    gsize suffix_size = allocation_size - length;
    gum_memory_release (aligned_base + length, suffix_size);
    allocation_size -= suffix_size;
  }

  g_assert (allocation_size == length);

  GumMemoryRange range;
  range.base_address = GPOINTER_TO_SIZE (aligned_base);
  range.size = length;
  gum_cloak_add_range (&range);

  return aligned_base;
}

bool
GumV8PageAllocator::FreePages (void * address,
                               size_t length)
{
  if (!gum_memory_free (address, length))
    return false;

  GumMemoryRange range;
  range.base_address = GPOINTER_TO_SIZE (address);
  range.size = length;
  gum_cloak_remove_range (&range);

  return true;
}

bool
GumV8PageAllocator::ReleasePages (void * address,
                                  size_t length,
                                  size_t new_length)
{
  const gpointer released_base = (guint8 *) address + new_length;
  const gsize released_size = length - new_length;
  if (!gum_memory_release (released_base, released_size))
    return false;

#ifndef HAVE_WINDOWS
  GumMemoryRange range;
  range.base_address = GPOINTER_TO_SIZE (released_base);
  range.size = released_size;
  gum_cloak_remove_range (&range);
#endif

  return true;
}

bool
GumV8PageAllocator::SetPermissions (void * address,
                                    size_t length,
                                    Permission permissions)
{
  GumPageProtection page_prot = gum_page_protection_from_v8 (permissions);

#ifndef HAVE_WINDOWS
  gboolean success;
  if (permissions == PageAllocator::kReadExecute &&
      gum_code_segment_is_supported ())
  {
    success = gum_code_segment_mark (address, length, NULL);
  }
  else
  {
    success = gum_try_mprotect (address, length, page_prot);
  }
  if (!success)
    return false;
#endif

  if (permissions == PageAllocator::kNoAccess)
    gum_memory_decommit (address, length);
  else
    gum_memory_commit (address, length, page_prot);

  return true;
}

void *
GumV8ArrayBufferAllocator::Allocate (size_t length)
{
  return g_malloc0 (MAX (length, 1));
}

void *
GumV8ArrayBufferAllocator::AllocateUninitialized (size_t length)
{
  return g_malloc (MAX (length, 1));
}

void
GumV8ArrayBufferAllocator::Free (void * data,
                                 size_t length)
{
  g_free (data);
}

MutexImpl *
GumV8ThreadingBackend::CreatePlainMutex ()
{
  return new GumMutex ();
}

MutexImpl *
GumV8ThreadingBackend::CreateRecursiveMutex ()
{
  return new GumRecursiveMutex ();
}

SharedMutexImpl *
GumV8ThreadingBackend::CreateSharedMutex ()
{
  return new GumSharedMutex ();
}

ConditionVariableImpl *
GumV8ThreadingBackend::CreateConditionVariable ()
{
  return new GumConditionVariable ();
}

GumMutex::GumMutex ()
{
  g_mutex_init (&mutex);
}

GumMutex::~GumMutex ()
{
  g_mutex_clear (&mutex);
}

void
GumMutex::Lock ()
{
  g_mutex_lock (&mutex);
}

void
GumMutex::Unlock ()
{
  g_mutex_unlock (&mutex);
}

bool
GumMutex::TryLock ()
{
  return !!g_mutex_trylock (&mutex);
}

GumRecursiveMutex::GumRecursiveMutex ()
{
  g_rec_mutex_init (&mutex);
}

GumRecursiveMutex::~GumRecursiveMutex ()
{
  g_rec_mutex_clear (&mutex);
}

void
GumRecursiveMutex::Lock ()
{
  g_rec_mutex_lock (&mutex);
}

void
GumRecursiveMutex::Unlock ()
{
  g_rec_mutex_unlock (&mutex);
}

bool
GumRecursiveMutex::TryLock ()
{
  return !!g_rec_mutex_trylock (&mutex);
}

GumSharedMutex::GumSharedMutex ()
{
  g_rw_lock_init (&lock);
}

GumSharedMutex::~GumSharedMutex ()
{
  g_rw_lock_clear (&lock);
}

void
GumSharedMutex::LockShared ()
{
  g_rw_lock_reader_lock (&lock);
}

void
GumSharedMutex::LockExclusive ()
{
  g_rw_lock_writer_lock (&lock);
}

void
GumSharedMutex::UnlockShared ()
{
  g_rw_lock_reader_unlock (&lock);
}

void
GumSharedMutex::UnlockExclusive ()
{
  g_rw_lock_writer_unlock (&lock);
}

bool
GumSharedMutex::TryLockShared ()
{
  return !!g_rw_lock_reader_trylock (&lock);
}

bool
GumSharedMutex::TryLockExclusive ()
{
  return !!g_rw_lock_writer_trylock (&lock);
}

GumConditionVariable::GumConditionVariable ()
{
  g_cond_init (&cond);
}

GumConditionVariable::~GumConditionVariable ()
{
  g_cond_clear (&cond);
}

void
GumConditionVariable::NotifyOne ()
{
  g_cond_signal (&cond);
}

void
GumConditionVariable::NotifyAll ()
{
  g_cond_broadcast (&cond);
}

void
GumConditionVariable::Wait (MutexImpl * mutex)
{
  GumMutex * m = (GumMutex *) mutex;
  g_cond_wait (&cond, &m->mutex);
}

bool
GumConditionVariable::WaitFor (MutexImpl * mutex,
                               int64_t delta_in_microseconds)
{
  GumMutex * m = (GumMutex *) mutex;
  gint64 deadline = g_get_monotonic_time () + delta_in_microseconds;
  return !!g_cond_wait_until (&cond, &m->mutex, deadline);
}

static GumPageProtection
gum_page_protection_from_v8 (PageAllocator::Permission permission)
{
  switch (permission)
  {
    case PageAllocator::kNoAccess:
      return GUM_PAGE_NO_ACCESS;
    case PageAllocator::kRead:
      return GUM_PAGE_READ;
    case PageAllocator::kReadWrite:
      return GUM_PAGE_RW;
    case PageAllocator::kReadExecute:
      return GUM_PAGE_RX;
    case PageAllocator::kReadWriteExecute:
    default:
      g_assert_not_reached ();
      return GUM_PAGE_NO_ACCESS;
  }
}
