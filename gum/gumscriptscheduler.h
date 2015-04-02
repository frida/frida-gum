/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SCHEDULER_H__
#define __GUM_SCRIPT_SCHEDULER_H__

#include <glib.h>

G_BEGIN_DECLS

typedef struct _GumScriptScheduler GumScriptScheduler;

typedef void (* GumScriptJobFunc) (gpointer user_data);

struct _GumScriptScheduler
{
  GMutex mutex;
  GCond cond;
  GSList * pending;
  GThreadPool * thread_pool;
};

G_GNUC_INTERNAL GumScriptScheduler * gum_script_scheduler_new (void);
G_GNUC_INTERNAL void gum_script_scheduler_free (
    GumScriptScheduler * scheduler);

G_GNUC_INTERNAL void gum_script_scheduler_push_job (GumScriptScheduler * self,
    GumScriptJobFunc job_func, gpointer user_data, GDestroyNotify notify,
    gpointer tag);
G_GNUC_INTERNAL void gum_script_scheduler_flush_by_tag (
    GumScriptScheduler * self, gpointer tag);

G_END_DECLS

#endif
