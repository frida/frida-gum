/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscripttask.h"

typedef struct _GumScriptJob GumScriptJob;

struct _GumScriptTaskPrivate
{
  gboolean disposed;
};

static void gum_script_task_dispose (GObject * obj);
static void gum_script_task_finalize (GObject * obj);

G_DEFINE_TYPE (GumScriptTask, gum_script_task, G_TYPE_OBJECT);

static void
gum_script_task_class_init (GumScriptTaskClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptTaskPrivate));

  object_class->dispose = gum_script_task_dispose;
  object_class->finalize = gum_script_task_finalize;
}

static void
gum_script_task_init (GumScriptTask * self)
{
  GumScriptTaskPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_SCRIPT_TASK,
      GumScriptTaskPrivate);
  priv = self->priv;
}

static void
gum_script_task_dispose (GObject * obj)
{
  GumScriptTask * self = GUM_SCRIPT_TASK (obj);
  GumScriptTaskPrivate * priv = self->priv;

  if (!priv->disposed)
  {
    priv->disposed = TRUE;
  }

  G_OBJECT_CLASS (gum_script_task_parent_class)->dispose (obj);
}

static void
gum_script_task_finalize (GObject * obj)
{
  GumScriptTask * self = GUM_SCRIPT_TASK (obj);
  GumScriptTaskPrivate * priv = self->priv;

  G_OBJECT_CLASS (gum_script_task_parent_class)->finalize (obj);
}

GumScriptTask *
gum_script_task_new (GumScriptTaskFunc func,
                     gpointer source_object,
                     GCancellable * cancellable,
                     GAsyncReadyCallback callback,
                     gpointer callback_data)
{
  return g_object_new (GUM_TYPE_SCRIPT_TASK, NULL);
}

GMainContext *
gum_script_task_get_context (GumScriptTask * self)
{
  return NULL;
}

void
gum_script_task_set_task_data (GumScriptTask * self,
                               gpointer task_data,
                               GDestroyNotify task_data_destroy)
{
}

void
gum_script_task_return_pointer (GumScriptTask * self,
                                gpointer result,
                                GDestroyNotify result_destroy)
{
}

void
gum_script_task_return_error (GumScriptTask * self,
                              GError * error)
{
}

gpointer
gum_script_task_propagate_pointer (GumScriptTask * self,
                                   GError ** error)
{
  return NULL;
}

void
gum_script_task_run_in_v8_thread (GumScriptTask * self,
                                  GumScriptScheduler * scheduler)
{
}

void
gum_script_task_run_in_v8_thread_sync (GumScriptTask * self,
                                       GumScriptScheduler * scheduler)
{
}

