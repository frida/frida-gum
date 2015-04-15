/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_PLATFORM_H__
#define __GUM_SCRIPT_PLATFORM_H__

#include "gumscriptbundle.h"
#include "gumscriptscheduler.h"

#include <v8.h>
#include <v8-platform.h>

class GumScriptPlatform : public v8::Platform
{
public:
  GumScriptPlatform ();
  ~GumScriptPlatform ();

  v8::Isolate * GetIsolate () const { return isolate; }
  GumScriptBundle * GetUserRuntime () const { return user_runtime; }
  GumScriptBundle * GetDebugRuntime () const { return debug_runtime; }
  GumScriptScheduler * GetScheduler () const { return scheduler; }

  virtual void CallOnBackgroundThread (v8::Task * task,
      ExpectedRuntime expected_runtime);
  virtual void CallOnForegroundThread (v8::Isolate * isolate, v8::Task * task);
  virtual double MonotonicallyIncreasingTime ();

private:
  void InitRuntime ();

  static void PerformTask (v8::Task * task);
  static void DisposeTask (v8::Task * task);

  v8::Isolate * isolate;
  GumScriptBundle * user_runtime;
  GumScriptBundle * debug_runtime;
  GumScriptScheduler * scheduler;
  const gint64 start_time;

  GumScriptPlatform (const GumScriptPlatform &);
  void operator= (const GumScriptPlatform &);
};

#endif
