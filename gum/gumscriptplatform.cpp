/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptplatform.h"

using namespace v8;

GumScriptPlatform::GumScriptPlatform (GumScriptScheduler * scheduler)
  : main_context (g_main_context_new ()),
    main_loop (g_main_loop_new (main_context, TRUE)),
    scheduler (scheduler),
    start_time (g_get_monotonic_time ())
{
  v8_thread = g_thread_new ("gum-v8-loop", (GThreadFunc) RunMainLoopWrapper,
      this);
}

GumScriptPlatform::~GumScriptPlatform ()
{
  CallOnForegroundThread (G_PRIORITY_LOW, (TaskFunc) g_main_loop_quit,
      main_loop, NULL);

  g_thread_join (v8_thread);
}

void
GumScriptPlatform::CallOnBackgroundThread (Task * task,
                        ExpectedRuntime expected_runtime)
{
  gum_script_scheduler_push_job (scheduler,
      (GumScriptJobFunc) PerformTask,
      task,
      (GDestroyNotify) DisposeTask,
      NULL);
}

void
GumScriptPlatform::CallOnForegroundThread (Isolate * isolate,
                                           Task * task)
{
  CallOnForegroundThread (G_PRIORITY_HIGH, (TaskFunc) PerformTask, task,
      (GDestroyNotify) DisposeTask);
}

void
GumScriptPlatform::CallOnForegroundThread (gint priority,
                                           TaskFunc func,
                                           gpointer data,
                                           GDestroyNotify notify)
{
  CallOnForegroundThreadData * d = g_slice_new (CallOnForegroundThreadData);
  d->func = func;
  d->data = data;
  d->notify = notify;

  GSource * source = g_idle_source_new ();
  g_source_set_priority (source, priority);
  g_source_set_callback (source,
      (GSourceFunc) CallOnForegroundThreadWhenIdle,
      d,
      (GDestroyNotify) CallOnForegroundThreadDataFree);
  g_source_attach (source, main_context);
  g_source_unref (source);
}

double
GumScriptPlatform::MonotonicallyIncreasingTime ()
{
  gint64 delta = g_get_monotonic_time () - start_time;
  return ((double) (delta / G_GINT64_CONSTANT (1000))) / 1000.0;
}

void
GumScriptPlatform::RunMainLoop ()
{
  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);
}

gpointer
GumScriptPlatform::RunMainLoopWrapper (GumScriptPlatform * self)
{
  self->RunMainLoop ();
  return NULL;
}

gboolean
GumScriptPlatform::CallOnForegroundThreadWhenIdle (CallOnForegroundThreadData * d)
{
  d->func (d->data);

  return FALSE;
}

void
GumScriptPlatform::CallOnForegroundThreadDataFree (CallOnForegroundThreadData * d)
{
  if (d->notify != NULL)
    d->notify (d->data);

  g_slice_free (CallOnForegroundThreadData, d);
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

