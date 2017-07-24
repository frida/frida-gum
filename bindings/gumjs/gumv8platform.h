/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_PLATFORM_H__
#define __GUM_V8_PLATFORM_H__

#include "gumv8bundle.h"
#include "gumscriptscheduler.h"

#include <v8-platform.h>

class GumV8DisposeRequest;
class GumV8TaskRequest;

class GumV8Platform : public v8::Platform
{
public:
  GumV8Platform ();
  ~GumV8Platform ();

  v8::Isolate * GetIsolate () const { return isolate; }
  GumV8Bundle * GetRuntimeBundle () const { return runtime_bundle; }
  const gchar * GetRuntimeSourceMap () const;
  GumV8Bundle * GetObjCBundle ();
  const gchar * GetObjCSourceMap () const;
  GumV8Bundle * GetJavaBundle ();
  const gchar * GetJavaSourceMap () const;
  GumV8Bundle * GetDebugBundle () const { return debug_bundle; }
  GumScriptScheduler * GetScheduler () const { return scheduler; }

  size_t NumberOfAvailableBackgroundThreads () override;
  void CallOnBackgroundThread (v8::Task * task,
      ExpectedRuntime expected_runtime) override;
  void CallOnForegroundThread (v8::Isolate * for_isolate,
      v8::Task * task) override;
  void CallDelayedOnForegroundThread (v8::Isolate * for_isolate,
      v8::Task * task, double delay_in_seconds) override;
  void CallIdleOnForegroundThread (v8::Isolate * for_isolate,
      v8::IdleTask * task) override;
  bool IdleTasksEnabled (v8::Isolate * for_isolate) override;
  double MonotonicallyIncreasingTime () override;
  v8::MemoryBackend * GetMemoryBackend () override;
  v8::ThreadingBackend * GetThreadingBackend () override;
  v8::TracingController * GetTracingController () override;

private:
  void InitRuntime ();
  static void PerformDispose (GumV8DisposeRequest * dispose_request);
  void Dispose (GumV8DisposeRequest * dispose_request);
  static void OnFatalError (const char * location, const char * message);

  static void HandleBackgroundTaskRequest (GumV8TaskRequest * request);
  static gboolean HandleForegroundTaskRequest (GumV8TaskRequest * request);
  void ScheduleForegroundTask (GumV8TaskRequest * request, GSource * source);
  void OnForegroundTaskPerformed (GumV8TaskRequest * request);

  GMutex lock;
  v8::Isolate * isolate;
  GumV8Bundle * runtime_bundle;
  GumV8Bundle * objc_bundle;
  GumV8Bundle * java_bundle;
  GumV8Bundle * debug_bundle;
  GumScriptScheduler * scheduler;
  const gint64 start_time;
  v8::ArrayBuffer::Allocator * array_buffer_allocator;
  v8::MemoryBackend * memory_backend;
  v8::ThreadingBackend * threading_backend;
  v8::TracingController * tracing_controller;
  GHashTable * pending_foreground_tasks;

  GumV8Platform (const GumV8Platform &);
  void operator= (const GumV8Platform &);

  friend class GumV8DisposeRequest;
};

#endif
