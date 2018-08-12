/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_PLATFORM_H__
#define __GUM_V8_PLATFORM_H__

#include "gumv8bundle.h"
#include "gumscriptscheduler.h"

#include <map>
#include <unordered_set>
#include <v8/v8-platform.h>

class GumV8Operation;
class GumV8MainContextOperation;
class GumV8ThreadPoolOperation;
class GumV8DelayedThreadPoolOperation;
class GumV8PlatformLocker;
class GumV8PlatformUnlocker;

class GumV8Platform : public v8::Platform
{
public:
  GumV8Platform ();
  GumV8Platform (const GumV8Platform &) = delete;
  GumV8Platform & operator= (const GumV8Platform &) = delete;
  ~GumV8Platform ();

  v8::Isolate * GetIsolate () const { return isolate; }
  GumV8Bundle * GetRuntimeBundle () const { return runtime_bundle; }
  const gchar * GetRuntimeSourceMap () const;
  GumV8Bundle * GetObjCBundle ();
  const gchar * GetObjCSourceMap () const;
  GumV8Bundle * GetJavaBundle ();
  const gchar * GetJavaSourceMap () const;
  GumScriptScheduler * GetScheduler () const { return scheduler; }
  std::shared_ptr<GumV8Operation> ScheduleOnJSThread (std::function<void ()> f);
  std::shared_ptr<GumV8Operation> ScheduleOnJSThread (gint priority,
      std::function<void ()> f);
  std::shared_ptr<GumV8Operation> ScheduleOnJSThreadDelayed (
      guint delay_in_milliseconds, std::function<void ()> f);
  std::shared_ptr<GumV8Operation> ScheduleOnJSThreadDelayed (
      guint delay_in_milliseconds, gint priority, std::function<void ()> f);
  std::shared_ptr<GumV8Operation> ScheduleOnThreadPool (
      std::function<void ()> f);
  std::shared_ptr<GumV8Operation> ScheduleOnThreadPoolDelayed (
      guint delay_in_milliseconds, std::function<void ()> f);

  int NumberOfWorkerThreads () override;
  std::shared_ptr<v8::TaskRunner> GetForegroundTaskRunner (
      v8::Isolate * isolate) override;
  void CallOnWorkerThread (std::unique_ptr<v8::Task> task) override;
  void CallDelayedOnWorkerThread (std::unique_ptr<v8::Task> task,
      double delay_in_seconds) override;
  void CallOnForegroundThread (v8::Isolate * isolate, v8::Task * task) override;
  void CallDelayedOnForegroundThread (v8::Isolate * isolate, v8::Task * task,
      double delay_in_seconds) override;
  void CallIdleOnForegroundThread (v8::Isolate * isolate,
      v8::IdleTask * task) override;
  bool IdleTasksEnabled (v8::Isolate * isolate) override;
  double MonotonicallyIncreasingTime () override;
  double CurrentClockTimeMillis () override;
  v8::MemoryBackend * GetMemoryBackend () override;
  v8::ThreadingBackend * GetThreadingBackend () override;
  v8::TracingController * GetTracingController () override;

private:
  void InitRuntime ();
  void Dispose ();
  void CancelPendingOperations ();
  static void OnFatalError (const char * location, const char * message);

  static gboolean PerformMainContextOperation (gpointer data);
  static void ReleaseMainContextOperation (gpointer data);
  static void PerformThreadPoolOperation (gpointer data);
  static void ReleaseThreadPoolOperation (gpointer data);
  static gboolean StartDelayedThreadPoolOperation (gpointer data);
  static void PerformDelayedThreadPoolOperation (gpointer data);
  static void ReleaseDelayedThreadPoolOperation (gpointer data);

  GMutex lock;
  v8::Isolate * isolate;
  GumV8Bundle * runtime_bundle;
  GumV8Bundle * objc_bundle;
  GumV8Bundle * java_bundle;
  GumScriptScheduler * scheduler;
  std::unordered_set<std::shared_ptr<GumV8Operation>> js_ops;
  std::unordered_set<std::shared_ptr<GumV8Operation>> pool_ops;
  std::map<v8::Isolate *, std::shared_ptr<v8::TaskRunner>> foreground_runners;
  const gint64 start_time;
  v8::ArrayBuffer::Allocator * array_buffer_allocator;
  v8::MemoryBackend * memory_backend;
  v8::ThreadingBackend * threading_backend;
  v8::TracingController * tracing_controller;

  friend class GumV8MainContextOperation;
  friend class GumV8ThreadPoolOperation;
  friend class GumV8DelayedThreadPoolOperation;
  friend class GumV8PlatformLocker;
  friend class GumV8PlatformUnlocker;
};

class GumV8Operation
{
public:
  GumV8Operation () = default;
  GumV8Operation (const GumV8Operation &) = delete;
  GumV8Operation & operator= (const GumV8Operation &) = delete;
  virtual ~GumV8Operation () = default;

  virtual void Cancel () = 0;
  virtual void Await () = 0;
};

#endif
