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

#ifndef __PROFILE_REPORT_HARNESS_H__
#define __PROFILE_REPORT_HARNESS_H__

#include "gumprofiler.h"

#include "fakesampler.h"

typedef struct _ProfileReportHarness ProfileReportHarness;

struct _ProfileReportHarness
{
  GumProfiler * profiler;

  GumSampler * sampler;
  GumFakeSampler * fake_sampler;

  GumProfileReport * report;
  const GPtrArray * root_nodes;
};

G_BEGIN_DECLS

void profile_report_harness_setup (ProfileReportHarness * h);
void profile_report_harness_setup_full (ProfileReportHarness * h,
    const gchar * func_match_str);
void profile_report_harness_teardown (ProfileReportHarness * h);

void profile_report_harness_assert_n_top_nodes (ProfileReportHarness * h,
    guint n, ...);
void profile_report_harness_assert_depth_from_root_node (
    ProfileReportHarness * h, guint root_node_index, ...);
void profile_report_harness_assert_same_xml (ProfileReportHarness * h,
    const gchar * expected_xml);

G_END_DECLS

#endif
