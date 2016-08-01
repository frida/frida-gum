/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SCHEDULER_H__
#define __GUM_SCRIPT_SCHEDULER_H__

#include <glib-object.h>

#define GUM_TYPE_SCRIPT_SCHEDULER (gum_script_scheduler_get_type ())
#define GUM_SCRIPT_SCHEDULER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT_SCHEDULER, GumScriptScheduler))
#define GUM_SCRIPT_SCHEDULER_CAST(obj) ((GumScriptScheduler *) (obj))
#define GUM_SCRIPT_SCHEDULER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_SCRIPT_SCHEDULER, GumScriptSchedulerClass))
#define GUM_IS_SCRIPT_SCHEDULER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT_SCHEDULER))
#define GUM_IS_SCRIPT_SCHEDULER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_SCRIPT_SCHEDULER))
#define GUM_SCRIPT_SCHEDULER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_SCRIPT_SCHEDULER, GumScriptSchedulerClass))

typedef struct _GumScriptScheduler GumScriptScheduler;
typedef struct _GumScriptSchedulerClass GumScriptSchedulerClass;

typedef struct _GumScriptSchedulerPrivate GumScriptSchedulerPrivate;

typedef struct _GumScriptJob GumScriptJob;
typedef void (* GumScriptJobFunc) (gpointer data);

struct _GumScriptScheduler
{
  GObject parent;

  GumScriptSchedulerPrivate * priv;
};

struct _GumScriptSchedulerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GType gum_script_scheduler_get_type (void) G_GNUC_CONST;

G_GNUC_INTERNAL GumScriptScheduler * gum_script_scheduler_new (void);

G_GNUC_INTERNAL GMainContext * gum_script_scheduler_get_js_context (
    GumScriptScheduler * self);

G_GNUC_INTERNAL void gum_script_scheduler_push_job_on_js_thread (
    GumScriptScheduler * self, gint priority, GumScriptJobFunc func,
    gpointer data, GDestroyNotify data_destroy);
G_GNUC_INTERNAL void gum_script_scheduler_push_job_on_thread_pool (
    GumScriptScheduler * self, GumScriptJobFunc func, gpointer data,
    GDestroyNotify data_destroy);

G_GNUC_INTERNAL GumScriptJob * gum_script_job_new (
    GumScriptScheduler * scheduler, GumScriptJobFunc func, gpointer data,
    GDestroyNotify data_destroy);
G_GNUC_INTERNAL void gum_script_job_free (GumScriptJob * job);
G_GNUC_INTERNAL void gum_script_job_start_on_js_thread (GumScriptJob * job);

G_END_DECLS

#endif
