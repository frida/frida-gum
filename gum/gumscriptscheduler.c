/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptscheduler.h"

#define GUM_SCRIPT_SCHEDULER_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_SCRIPT_SCHEDULER_UNLOCK() (g_mutex_unlock (&priv->mutex))

typedef struct _GumScriptJob GumScriptJob;

struct _GumScriptSchedulerPrivate
{
  gboolean disposed;

  GMutex mutex;
  GCond cond;

  GThread * v8_thread;
  GMainLoop * v8_loop;
  GMainContext * v8_context;

  GThreadPool * thread_pool;

  GSList * pending;
};

struct _GumScriptJob
{
  GumScriptJobFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
  gpointer tag;

  GumScriptScheduler * scheduler;
};

static void gum_script_scheduler_dispose (GObject * obj);
static void gum_script_scheduler_finalize (GObject * obj);

static gboolean gum_script_scheduler_perform_v8_job (
    GumScriptJob * job);
static void gum_script_scheduler_perform_pool_job (GumScriptJob * job,
    GumScriptScheduler * self);

static gpointer gum_script_scheduler_run_v8_loop (GumScriptScheduler * self);

static GumScriptJob * gum_script_job_new (
    GumScriptScheduler * self, GumScriptJobFunc func, gpointer data,
    GDestroyNotify data_destroy, gpointer tag);
static void gum_script_job_free (GumScriptJob * job);

G_DEFINE_TYPE (GumScriptScheduler, gum_script_scheduler, G_TYPE_OBJECT);

static void
gum_script_scheduler_class_init (GumScriptSchedulerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptSchedulerPrivate));

  object_class->dispose = gum_script_scheduler_dispose;
  object_class->finalize = gum_script_scheduler_finalize;
}

static void
gum_script_scheduler_init (GumScriptScheduler * self)
{
  GumScriptSchedulerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_SCRIPT_SCHEDULER,
      GumScriptSchedulerPrivate);
  priv = self->priv;

  g_mutex_init (&priv->mutex);
  g_cond_init (&priv->cond);

  priv->v8_context = g_main_context_new ();
  priv->v8_loop = g_main_loop_new (priv->v8_context, TRUE);

  priv->v8_thread = g_thread_new ("gum-v8-loop",
      (GThreadFunc) gum_script_scheduler_run_v8_loop, self);

  priv->thread_pool = g_thread_pool_new (
      (GFunc) gum_script_scheduler_perform_pool_job,
      self,
      4,
      FALSE,
      NULL);
}

static void
gum_script_scheduler_dispose (GObject * obj)
{
  GumScriptScheduler * self = GUM_SCRIPT_SCHEDULER (obj);
  GumScriptSchedulerPrivate * priv = self->priv;

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    g_thread_pool_free (priv->thread_pool, FALSE, TRUE);
    priv->thread_pool = NULL;

    gum_script_scheduler_push_job_on_v8_thread (self, G_PRIORITY_LOW,
        (GumScriptJobFunc) g_main_loop_quit, priv->v8_loop, NULL, NULL);
    g_thread_join (priv->v8_thread);
    priv->v8_thread = NULL;

    g_main_loop_unref (priv->v8_loop);
    priv->v8_loop = NULL;

    g_main_context_unref (priv->v8_context);
    priv->v8_context = NULL;
  }

  g_assert (priv->pending == NULL);

  G_OBJECT_CLASS (gum_script_scheduler_parent_class)->dispose (obj);
}

static void
gum_script_scheduler_finalize (GObject * obj)
{
  GumScriptScheduler * self = GUM_SCRIPT_SCHEDULER (obj);
  GumScriptSchedulerPrivate * priv = self->priv;

  g_cond_clear (&priv->cond);
  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (gum_script_scheduler_parent_class)->finalize (obj);
}

GumScriptScheduler *
gum_script_scheduler_new (void)
{
  return g_object_new (GUM_TYPE_SCRIPT_SCHEDULER, NULL);
}

GMainContext *
gum_script_scheduler_get_v8_context (GumScriptScheduler * self)
{
  return self->priv->v8_context;
}

void
gum_script_scheduler_push_job_on_v8_thread (GumScriptScheduler * self,
                                            gint priority,
                                            GumScriptJobFunc func,
                                            gpointer data,
                                            GDestroyNotify data_destroy,
                                            gpointer tag)
{
  GumScriptJob * job;
  GSource * source;

  job = gum_script_job_new (self, func, data, data_destroy, tag);

  source = g_idle_source_new ();
  g_source_set_priority (source, priority);
  g_source_set_callback (source,
      (GSourceFunc) gum_script_scheduler_perform_v8_job,
      job,
      (GDestroyNotify) gum_script_job_free);
  g_source_attach (source, self->priv->v8_context);
  g_source_unref (source);
}

void
gum_script_scheduler_push_job_on_thread_pool (GumScriptScheduler * self,
                                              GumScriptJobFunc func,
                                              gpointer data,
                                              GDestroyNotify data_destroy,
                                              gpointer tag)
{
  g_thread_pool_push (self->priv->thread_pool,
      gum_script_job_new (self, func, data, data_destroy, tag),
      NULL);
}

void
gum_script_scheduler_flush_by_tag (GumScriptScheduler * self,
                                   gpointer tag)
{
  GumScriptSchedulerPrivate * priv = self->priv;
  GSList * cur;
  gboolean found;

  GUM_SCRIPT_SCHEDULER_LOCK ();

  do
  {
    found = FALSE;

    for (cur = priv->pending; cur != NULL && !found; cur = cur->next)
    {
      GumScriptJob * job = cur->data;
      if (job->tag == tag)
        found = TRUE;
    }

    if (found)
      g_cond_wait (&priv->cond, &priv->mutex);
  }
  while (found);

  GUM_SCRIPT_SCHEDULER_UNLOCK ();
}

static void
gum_script_scheduler_on_job_created (GumScriptScheduler * self,
                                   GumScriptJob * job)
{
  GumScriptSchedulerPrivate * priv = self->priv;

  if (job->tag == NULL)
    return;

  GUM_SCRIPT_SCHEDULER_LOCK ();
  priv->pending = g_slist_prepend (priv->pending, job);
  GUM_SCRIPT_SCHEDULER_UNLOCK ();
}

static void
gum_script_scheduler_on_job_destroyed (GumScriptScheduler * self,
                                       GumScriptJob * job)
{
  GumScriptSchedulerPrivate * priv = self->priv;

  if (job->tag == NULL)
    return;

  GUM_SCRIPT_SCHEDULER_LOCK ();
  priv->pending = g_slist_remove (priv->pending, job);
  g_cond_broadcast (&priv->cond);
  GUM_SCRIPT_SCHEDULER_UNLOCK ();
}

static gboolean
gum_script_scheduler_perform_v8_job (GumScriptJob * job)
{
  job->func (job->data);

  return FALSE;
}

static void
gum_script_scheduler_perform_pool_job (GumScriptJob * job,
                                       GumScriptScheduler * self)
{
  job->func (job->data);

  gum_script_job_free (job);
}

static gpointer
gum_script_scheduler_run_v8_loop (GumScriptScheduler * self)
{
  GumScriptSchedulerPrivate * priv = self->priv;

  g_main_context_push_thread_default (priv->v8_context);
  g_main_loop_run (priv->v8_loop);
  g_main_context_pop_thread_default (priv->v8_context);

  return NULL;
}

static GumScriptJob *
gum_script_job_new (GumScriptScheduler * scheduler,
                    GumScriptJobFunc func,
                    gpointer data,
                    GDestroyNotify data_destroy,
                    gpointer tag)
{
  GumScriptJob * job;

  job = g_slice_new (GumScriptJob);
  job->func = func;
  job->data = data;
  job->data_destroy = data_destroy;
  job->tag = tag;

  job->scheduler = scheduler;

  gum_script_scheduler_on_job_created (scheduler, job);

  return job;
}

static void
gum_script_job_free (GumScriptJob * job)
{
  gum_script_scheduler_on_job_destroyed (job->scheduler, job);

  if (job->data_destroy != NULL)
    job->data_destroy (job->data);

  g_slice_free (GumScriptJob, job);
}
