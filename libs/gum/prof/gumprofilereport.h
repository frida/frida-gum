/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __GUM_PROFILE_REPORT_H__
#define __GUM_PROFILE_REPORT_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/prof/gumsampler.h>

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
