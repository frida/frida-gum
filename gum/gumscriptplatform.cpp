/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptplatform.h"

using namespace v8;

GumScriptPlatform::GumScriptPlatform (GumScriptScheduler * scheduler)
  : scheduler (scheduler),
    start_time (g_get_monotonic_time ())
{
}

void
GumScriptPlatform::CallOnBackgroundThread (Task * task,
                                           ExpectedRuntime expected_runtime)
{
  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask, NULL);
}

void
GumScriptPlatform::CallOnForegroundThread (Isolate * isolate,
                                           Task * task)
{
  gum_script_scheduler_push_job_on_v8_thread (scheduler, G_PRIORITY_HIGH,
      (GumScriptJobFunc) PerformTask, task, (GDestroyNotify) DisposeTask, NULL);
}

double
GumScriptPlatform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;
  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

void
GumScriptPlatform::PerformTask (Task * task)
{
  task->Run ();
}

void
GumScriptPlatform::DisposeTask (Task * task)
{
  delete task;
}

