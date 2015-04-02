/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptscheduler.h"

#define GUM_SCRIPT_SCHEDULER_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_SCRIPT_SCHEDULER_UNLOCK() (g_mutex_unlock (&self->mutex))

typedef struct _GumScriptJob GumScriptJob;

struct _GumScriptJob
{
  GumScriptJobFunc func;
  gpointer user_data;
  GDestroyNotify notify;
  gpointer tag;
};

static void gum_script_scheduler_perform (GumScriptJob * job,
    GumScriptScheduler * self);

GumScriptScheduler *
gum_script_scheduler_new (void)
{
  GumScriptScheduler * scheduler;

  scheduler = g_slice_new (GumScriptScheduler);
  g_mutex_init (&scheduler->mutex);
  g_cond_init (&scheduler->cond);
  scheduler->pending = NULL;
  scheduler->thread_pool = g_thread_pool_new (
      (GFunc) gum_script_scheduler_perform,
      scheduler,
      4,
      FALSE,
      NULL);

  return scheduler;
}

void
gum_script_scheduler_free (GumScriptScheduler * scheduler)
{
  g_thread_pool_free (scheduler->thread_pool, FALSE, TRUE);
  g_assert (scheduler->pending == NULL);
  g_cond_clear (&scheduler->cond);
  g_mutex_clear (&scheduler->mutex);
  g_slice_free (GumScriptScheduler, scheduler);
}

void
gum_script_scheduler_push_job (GumScriptScheduler * self,
                               GumScriptJobFunc job_func,
                               gpointer user_data,
                               GDestroyNotify notify,
                               gpointer tag)
{
  GumScriptJob * job;

  job = g_slice_new (GumScriptJob);
  job->func = job_func;
  job->user_data = user_data;
  job->notify = notify;
  job->tag = tag;

  if (tag != NULL)
  {
    GUM_SCRIPT_SCHEDULER_LOCK ();
    self->pending = g_slist_prepend (self->pending, job);
    GUM_SCRIPT_SCHEDULER_UNLOCK ();
  }

  g_thread_pool_push (self->thread_pool, job, NULL);
}

void
gum_script_scheduler_flush_by_tag (GumScriptScheduler * self,
                                   gpointer tag)
{
  GSList * cur;
  gboolean found;

  GUM_SCRIPT_SCHEDULER_LOCK ();

  do
  {
    found = FALSE;

    for (cur = self->pending; cur != NULL && !found; cur = cur->next)
    {
      GumScriptJob * job = cur->data;
      if (job->tag == tag)
        found = TRUE;
    }

    if (found)
      g_cond_wait (&self->cond, &self->mutex);
  }
  while (found);

  GUM_SCRIPT_SCHEDULER_UNLOCK ();
}

static void
gum_script_scheduler_perform (GumScriptJob * job,
                              GumScriptScheduler * self)
{
  job->func (job->user_data);
  job->notify (job->user_data);

  if (job->tag != NULL)
  {
    GUM_SCRIPT_SCHEDULER_LOCK ();
    self->pending = g_slist_remove (self->pending, job);
    g_cond_broadcast (&self->cond);
    GUM_SCRIPT_SCHEDULER_UNLOCK ();
  }

  g_slice_free (GumScriptJob, job);
}

