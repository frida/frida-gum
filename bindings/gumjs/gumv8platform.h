/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_PLATFORM_H__
#define __GUM_V8_PLATFORM_H__

#include "gumv8bundle.h"
#include "gumscriptscheduler.h"

#include <v8.h>
#include <v8-platform.h>

template<class T> class GumV8TaskRequest;

class GumV8Platform : public v8::Platform
{
public:
  GumV8Platform ();
  ~GumV8Platform ();

  v8::Isolate * GetIsolate () const { return isolate; }
  GumV8Bundle * GetUserRuntime () const { return user_runtime; }
  GumV8Bundle * GetDebugRuntime () const { return debug_runtime; }
  GumScriptScheduler * GetScheduler () const { return scheduler; }

  virtual size_t NumberOfAvailableBackgroundThreads ();
  virtual void CallOnBackgroundThread (v8::Task * task,
      ExpectedRuntime expected_runtime);
  virtual void CallOnForegroundThread (v8::Isolate * for_isolate,
      v8::Task * task);
  virtual void CallDelayedOnForegroundThread (v8::Isolate * for_isolate,
      v8::Task * task, double delay_in_seconds);
  virtual void CallIdleOnForegroundThread (v8::Isolate * for_isolate,
      v8::IdleTask * task);
  virtual bool IdleTasksEnabled (v8::Isolate * for_isolate);
  virtual double MonotonicallyIncreasingTime ();

private:
  void InitRuntime ();
  static void OnFatalError (const char * location, const char * message);

  static void HandleTaskRequest (GumV8TaskRequest<v8::Task> * request);
  static gboolean HandleDelayedTaskRequest (
      GumV8TaskRequest<v8::Task> * request);
  static void HandleIdleTaskRequest (GumV8TaskRequest<v8::IdleTask> * request);

  bool disposing;
  v8::Isolate * isolate;
  GumV8Bundle * user_runtime;
  GumV8Bundle * debug_runtime;
  GumScriptScheduler * scheduler;
  const gint64 start_time;
  v8::ArrayBuffer::Allocator * array_buffer_allocator;

  GumV8Platform (const GumV8Platform &);
  void operator= (const GumV8Platform &);
};

#endif
