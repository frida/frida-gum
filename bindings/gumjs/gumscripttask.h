/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_TASK_H__
#define __GUM_SCRIPT_TASK_H__

#include "gumscriptscheduler.h"

#include <gio/gio.h>

#define GUM_TYPE_SCRIPT_TASK (gum_script_task_get_type ())
#define GUM_SCRIPT_TASK(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT_TASK, GumScriptTask))
#define GUM_SCRIPT_TASK_CAST(obj) ((GumScriptTask *) (obj))
#define GUM_SCRIPT_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_SCRIPT_TASK, GumScriptTaskClass))
#define GUM_IS_SCRIPT_TASK(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT_TASK))
#define GUM_IS_SCRIPT_TASK_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_SCRIPT_TASK))
#define GUM_SCRIPT_TASK_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_SCRIPT_TASK, GumScriptTaskClass))

typedef struct _GumScriptTask GumScriptTask;
typedef struct _GumScriptTaskClass GumScriptTaskClass;

typedef struct _GumScriptTaskPrivate GumScriptTaskPrivate;

typedef void (* GumScriptTaskFunc) (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);

struct _GumScriptTask
{
  GObject parent;

  GumScriptTaskPrivate * priv;
};

struct _GumScriptTaskClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_script_task_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL GumScriptTask * gum_script_task_new (GumScriptTaskFunc func,
    gpointer source_object, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer callback_data);
G_GNUC_INTERNAL gpointer gum_script_task_get_source_object (
    GumScriptTask * self);
G_GNUC_INTERNAL gpointer gum_script_task_get_source_tag (GumScriptTask * self);
G_GNUC_INTERNAL void gum_script_task_set_source_tag (GumScriptTask * self,
    gpointer source_tag);
G_GNUC_INTERNAL GMainContext * gum_script_task_get_context (
    GumScriptTask * self);
G_GNUC_INTERNAL void gum_script_task_set_task_data (GumScriptTask * self,
    gpointer task_data, GDestroyNotify task_data_destroy);

G_GNUC_INTERNAL void gum_script_task_return_pointer (GumScriptTask * self,
    gpointer result, GDestroyNotify result_destroy);
G_GNUC_INTERNAL void gum_script_task_return_error (GumScriptTask * self,
    GError * error);

G_GNUC_INTERNAL gpointer gum_script_task_propagate_pointer (
    GumScriptTask * self, GError ** error);

G_GNUC_INTERNAL void gum_script_task_run_in_js_thread (GumScriptTask * self,
    GumScriptScheduler * scheduler);
G_GNUC_INTERNAL void gum_script_task_run_in_js_thread_sync (
    GumScriptTask * self, GumScriptScheduler * scheduler);

G_END_DECLS

#endif
