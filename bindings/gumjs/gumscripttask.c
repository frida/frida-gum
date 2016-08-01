/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscripttask.h"

struct _GumScriptTaskPrivate
{
  gboolean disposed;

  GumScriptTaskFunc func;
  gpointer source_object;
  gpointer source_tag;
  GCancellable * cancellable;
  GAsyncReadyCallback callback;
  gpointer callback_data;
  gpointer task_data;
  GDestroyNotify task_data_destroy;

  GMainContext * context;

  gboolean synchronous;
  GMutex mutex;
  GCond cond;

  volatile gboolean completed;
  gpointer result;
  GDestroyNotify result_destroy;
  GError * error;
};

static void gum_script_task_iface_init (GAsyncResultIface * iface);
static void gum_script_task_dispose (GObject * obj);
static void gum_script_task_finalize (GObject * obj);

static gpointer gum_script_task_get_user_data (GAsyncResult * res);
static GObject * gum_script_task_ref_source_object (GAsyncResult * res);
static gboolean gum_script_task_is_tagged (GAsyncResult * res,
    gpointer source_tag);

static void gum_script_task_return (GumScriptTask * self);

static gboolean gum_script_task_propagate_error (GumScriptTask * self,
    GError ** error);

static void gum_script_task_run (GumScriptTask * self);
static gboolean gum_script_task_complete (GumScriptTask * self);

G_DEFINE_TYPE_EXTENDED (GumScriptTask,
                        gum_script_task,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_RESULT,
                            gum_script_task_iface_init));

static void
gum_script_task_class_init (GumScriptTaskClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptTaskPrivate));

  object_class->dispose = gum_script_task_dispose;
  object_class->finalize = gum_script_task_finalize;
}

static void
gum_script_task_iface_init (GAsyncResultIface * iface)
{
  iface->get_user_data = gum_script_task_get_user_data;
  iface->get_source_object = gum_script_task_ref_source_object;
  iface->is_tagged = gum_script_task_is_tagged;
}

static void
gum_script_task_init (GumScriptTask * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_SCRIPT_TASK,
      GumScriptTaskPrivate);
}

static void
gum_script_task_dispose (GObject * obj)
{
  GumScriptTask * self = GUM_SCRIPT_TASK (obj);
  GumScriptTaskPrivate * priv = self->priv;

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    g_main_context_unref (priv->context);
    priv->context = NULL;

    if (priv->cancellable != NULL)
    {
      g_object_unref (priv->cancellable);
      priv->cancellable = NULL;
    }

    if (priv->source_object != NULL)
    {
      g_object_unref (priv->source_object);
      priv->source_object = NULL;
    }
  }

  G_OBJECT_CLASS (gum_script_task_parent_class)->dispose (obj);
}

static void
gum_script_task_finalize (GObject * obj)
{
  GumScriptTask * self = GUM_SCRIPT_TASK (obj);
  GumScriptTaskPrivate * priv = self->priv;

  if (priv->error != NULL)
    g_error_free (priv->error);

  if (priv->result_destroy != NULL)
    priv->result_destroy (priv->result);

  if (priv->task_data_destroy != NULL)
    priv->task_data_destroy (priv->task_data);

  G_OBJECT_CLASS (gum_script_task_parent_class)->finalize (obj);
}

GumScriptTask *
gum_script_task_new (GumScriptTaskFunc func,
                     gpointer source_object,
                     GCancellable * cancellable,
                     GAsyncReadyCallback callback,
                     gpointer callback_data)
{
  GumScriptTask * task;
  GumScriptTaskPrivate * priv;

  task = g_object_new (GUM_TYPE_SCRIPT_TASK, NULL);
  priv = task->priv;

  priv->func = func;
  priv->source_object =
      (source_object != NULL) ? g_object_ref (source_object) : NULL;
  priv->cancellable =
      (cancellable != NULL) ? g_object_ref (cancellable) : NULL;
  priv->callback = callback;
  priv->callback_data = callback_data;

  priv->context = g_main_context_ref_thread_default ();

  return task;
}

static gpointer
gum_script_task_get_user_data (GAsyncResult * res)
{
  return GUM_SCRIPT_TASK (res)->priv->callback_data;
}

static GObject *
gum_script_task_ref_source_object (GAsyncResult * res)
{
  GumScriptTask * self = GUM_SCRIPT_TASK (res);
  GumScriptTaskPrivate * priv = self->priv;

  if (priv->source_object == NULL)
    return NULL;

  return g_object_ref (priv->source_object);
}

static gboolean
gum_script_task_is_tagged (GAsyncResult * res,
                           gpointer source_tag)
{
  return GUM_SCRIPT_TASK (res)->priv->source_tag == source_tag;
}

gpointer
gum_script_task_get_source_object (GumScriptTask * self)
{
  return self->priv->source_object;
}

gpointer
gum_script_task_get_source_tag (GumScriptTask * self)
{
  return self->priv->source_tag;
}

void
gum_script_task_set_source_tag (GumScriptTask * self,
                                gpointer source_tag)
{
  self->priv->source_tag = source_tag;
}

GMainContext *
gum_script_task_get_context (GumScriptTask * self)
{
  return self->priv->context;
}

void
gum_script_task_set_task_data (GumScriptTask * self,
                               gpointer task_data,
                               GDestroyNotify task_data_destroy)
{
  GumScriptTaskPrivate * priv = self->priv;

  priv->task_data = task_data;
  priv->task_data_destroy = task_data_destroy;
}

void
gum_script_task_return_pointer (GumScriptTask * self,
                                gpointer result,
                                GDestroyNotify result_destroy)
{
  GumScriptTaskPrivate * priv = self->priv;

  priv->result = result;
  priv->result_destroy = result_destroy;

  gum_script_task_return (self);
}

void
gum_script_task_return_error (GumScriptTask * self,
                              GError * error)
{
  self->priv->error = error;

  gum_script_task_return (self);
}

static void
gum_script_task_return (GumScriptTask * self)
{
  GumScriptTaskPrivate * priv = self->priv;

  if (priv->synchronous)
  {
    g_mutex_lock (&priv->mutex);
    priv->completed = TRUE;
    g_cond_signal (&priv->cond);
    g_mutex_unlock (&priv->mutex);
  }
  else
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_callback (source, (GSourceFunc) gum_script_task_complete,
        g_object_ref (self), g_object_unref);
    g_source_attach (source, priv->context);
    g_source_unref (source);
  }
}

gpointer
gum_script_task_propagate_pointer (GumScriptTask * self,
                                   GError ** error)
{
  GumScriptTaskPrivate * priv = self->priv;

  if (gum_script_task_propagate_error (self, error))
    return NULL;

  priv->result_destroy = NULL;

  return priv->result;
}

static gboolean
gum_script_task_propagate_error (GumScriptTask * self,
                                 GError ** error)
{
  GumScriptTaskPrivate * priv = self->priv;

  if (g_cancellable_set_error_if_cancelled (priv->cancellable, error))
    return TRUE;

  if (priv->error != NULL)
  {
    g_propagate_error (error, priv->error);
    priv->error = NULL;
    return TRUE;
  }

  return FALSE;
}

void
gum_script_task_run_in_js_thread (GumScriptTask * self,
                                  GumScriptScheduler * scheduler)
{
  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) gum_script_task_run, g_object_ref (self),
      g_object_unref);
}

void
gum_script_task_run_in_js_thread_sync (GumScriptTask * self,
                                       GumScriptScheduler * scheduler)
{
  GumScriptTaskPrivate * priv = self->priv;

  priv->synchronous = TRUE;

  g_mutex_init (&priv->mutex);
  g_cond_init (&priv->cond);

  gum_script_scheduler_push_job_on_js_thread (scheduler, G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) gum_script_task_run, g_object_ref (self),
      g_object_unref);

  g_mutex_lock (&priv->mutex);
  while (!priv->completed)
    g_cond_wait (&priv->cond, &priv->mutex);
  g_mutex_unlock (&priv->mutex);

  g_cond_clear (&priv->cond);
  g_mutex_clear (&priv->mutex);
}

static void
gum_script_task_run (GumScriptTask * self)
{
  GumScriptTaskPrivate * priv = self->priv;

  if (priv->cancellable == NULL ||
      !g_cancellable_is_cancelled (priv->cancellable))
  {
    priv->func (self, priv->source_object, priv->task_data, priv->cancellable);
  }
}

static gboolean
gum_script_task_complete (GumScriptTask * self)
{
  GumScriptTaskPrivate * priv = self->priv;

  if (priv->callback != NULL)
  {
    priv->callback (priv->source_object, G_ASYNC_RESULT (self),
        priv->callback_data);
  }

  return FALSE;
}

