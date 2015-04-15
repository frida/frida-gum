/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_PLATFORM_H__
#define __GUM_SCRIPT_PLATFORM_H__

#include "gumscriptscheduler.h"

#include <v8.h>
#include <v8-platform.h>

class GumScriptPlatform : public v8::Platform
{
public:
  GumScriptPlatform ();
  ~GumScriptPlatform ();

  v8::Isolate * GetIsolate () const;
  v8::Local<v8::UnboundScript> GetRuntime () const;
  GumScriptScheduler * GetScheduler () const;

  virtual void CallOnBackgroundThread (v8::Task * task,
      ExpectedRuntime expected_runtime);
  virtual void CallOnForegroundThread (v8::Isolate * isolate, v8::Task * task);
  virtual double MonotonicallyIncreasingTime ();

private:
  void InitRuntime ();

  static void PerformTask (v8::Task * task);
  static void DisposeTask (v8::Task * task);

  v8::Isolate * isolate;
  v8::Persistent<v8::UnboundScript> runtime;
  GumScriptScheduler * scheduler;
  const gint64 start_time;

  GumScriptPlatform (const GumScriptPlatform &);
  void operator= (const GumScriptPlatform &);
};

#endif
