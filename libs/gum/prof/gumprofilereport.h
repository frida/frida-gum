/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROFILE_REPORT_H__
#define __GUM_PROFILE_REPORT_H__

#include "gumsampler.h"

#define GUM_TYPE_PROFILE_REPORT (gum_profile_report_get_type ())
#define GUM_PROFILE_REPORT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_PROFILE_REPORT, GumProfileReport))
#define GUM_PROFILE_REPORT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_PROFILE_REPORT, GumProfileReportClass))
#define GUM_IS_PROFILE_REPORT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_PROFILE_REPORT))
#define GUM_IS_PROFILE_REPORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_PROFILE_REPORT))
#define GUM_PROFILE_REPORT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_PROFILE_REPORT, GumProfileReportClass))

typedef struct _GumProfileReport GumProfileReport;
typedef struct _GumProfileReportClass GumProfileReportClass;

typedef struct _GumProfileReportPrivate GumProfileReportPrivate;

typedef struct _GumProfileReportNode GumProfileReportNode;

struct _GumProfileReport
{
  GObject parent;

  GumProfileReportPrivate * priv;
};

struct _GumProfileReportClass
{
  GObjectClass parent_class;
};

struct _GumProfileReportNode
{
  gchar * name;
  guint64 total_calls;
  GumSample total_duration;
  GumSample worst_case_duration;
  gchar * worst_case_info;
  GumProfileReportNode * child;
};

G_BEGIN_DECLS

GUM_API GType gum_profile_report_get_type (void) G_GNUC_CONST;

GUM_API GumProfileReport * gum_profile_report_new (void);

GUM_API gchar * gum_profile_report_emit_xml (GumProfileReport * self);

GUM_API GPtrArray * gum_profile_report_get_root_nodes_for_thread (
    GumProfileReport * self, guint thread_index);

void _gum_profile_report_append_thread_root_node (
    GumProfileReport * self, guint thread_id,
    GumProfileReportNode * root_node);
void _gum_profile_report_sort (GumProfileReport * self);

G_END_DECLS

#endif
