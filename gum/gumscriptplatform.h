/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_PLATFORM_H__
#define __GUM_SCRIPT_PLATFORM_H__

#include "gumscriptscheduler.h"

#include <glib.h>
#include <v8-platform.h>

class GumScriptPlatform : public v8::Platform
{
public:
  typedef void (* TaskFunc) (gpointer data);

  GumScriptPlatform (GumScriptScheduler * scheduler);
  ~GumScriptPlatform ();

  virtual void CallOnBackgroundThread (v8::Task * task,
      ExpectedRuntime expected_runtime);
  virtual void CallOnForegroundThread (v8::Isolate * isolate, v8::Task * task);
  void CallOnForegroundThread (gint priority, TaskFunc func, gpointer data,
      GDestroyNotify notify);

  virtual double MonotonicallyIncreasingTime ();

private:
  void RunMainLoop ();

  static gpointer RunMainLoopWrapper (GumScriptPlatform * self);

  struct CallOnForegroundThreadData
  {
    TaskFunc func;
    gpointer data;
    GDestroyNotify notify;
  };

  static gboolean CallOnForegroundThreadWhenIdle (
      CallOnForegroundThreadData * d);
  static void CallOnForegroundThreadDataFree (CallOnForegroundThreadData * d);

  static void PerformTask (v8::Task * task);
  static void DisposeTask (v8::Task * task);

  GThread * v8_thread;
  GMainContext * main_context;
  GMainLoop * main_loop;
  GumScriptScheduler * scheduler;
  const gint64 start_time;

  GumScriptPlatform (const GumScriptPlatform &);
  void operator= (const GumScriptPlatform &);
};

#endif
