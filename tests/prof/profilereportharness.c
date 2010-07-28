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

#include "profilereportharness.h"

#include "testutil.h"

#include <string.h>

static const GPtrArray * profile_report_harness_get_root_nodes (
    ProfileReportHarness * h);

void
profile_report_harness_setup (ProfileReportHarness * h)
{
  profile_report_harness_setup_full (h, "example_*");
}

void
profile_report_harness_setup_full (ProfileReportHarness * h,
                                   const gchar * func_match_str)
{
  h->profiler = gum_profiler_new ();
  h->sampler = gum_fake_sampler_new ();
  h->fake_sampler = GUM_FAKE_SAMPLER (h->sampler);
  h->report = NULL;
  h->root_nodes = NULL;

  if (func_match_str != NULL)
  {
    gum_profiler_instrument_functions_matching (h->profiler, func_match_str,
        h->sampler, NULL);
  }
}

void
profile_report_harness_teardown (ProfileReportHarness * h)
{
  g_object_unref (h->report);
  g_object_unref (h->sampler);
  g_object_unref (h->profiler);
}

void
profile_report_harness_assert_n_top_nodes (ProfileReportHarness * h,
                                           guint n,
                                           ...)
{
  const GPtrArray * root_nodes;
  va_list args;
  guint i;

  root_nodes = profile_report_harness_get_root_nodes (h);
  g_assert_cmpuint (root_nodes->len, ==, n);

  va_start (args, n);

  for (i = 0; i < n; i++)
  {
    const gchar * name, * child_name;
    GumProfileReportNode * node;

    name = va_arg (args, const gchar *);
    child_name = va_arg (args, const gchar *);

    node = g_ptr_array_index (root_nodes, i);
    g_assert_cmpstr (node->name, ==, name);
    g_assert (node->child != NULL);
    g_assert_cmpstr (node->child->name, ==, child_name);
  }
}

void
profile_report_harness_assert_depth_from_root_node (ProfileReportHarness * h,
                                                    guint root_node_index,
                                                    ...)
{
  GumProfileReportNode * root_node, * cur_node;
  va_list args;

  root_node = g_ptr_array_index (h->root_nodes, root_node_index);
  cur_node = root_node;

  va_start (args, root_node_index);

  while (TRUE)
  {
    const gchar * expected_node_name;

    expected_node_name = va_arg (args, const gchar *);
    if (expected_node_name == NULL)
    {
      g_assert (cur_node == NULL);
      break;
    }

    g_assert_cmpstr (cur_node->name, ==, expected_node_name);

    cur_node = cur_node->child;
  }
}

static const GPtrArray *
profile_report_harness_get_root_nodes (ProfileReportHarness * h)
{
  h->report = gum_profiler_generate_report (h->profiler);
  g_assert (h->report != NULL);

  h->root_nodes = gum_profile_report_get_root_nodes_for_thread (h->report, 0);
  g_assert (h->root_nodes != NULL);

  return h->root_nodes;
}

void
profile_report_harness_assert_same_xml (ProfileReportHarness * h,
                                        const gchar * expected_xml)
{
  gchar * generated_xml;

  h->report = gum_profiler_generate_report (h->profiler);
  g_assert (h->report != NULL);

  generated_xml = gum_profile_report_emit_xml (h->report);
  if (strcmp (generated_xml, expected_xml) != 0)
  {
    GString * message;
    gchar * diff;

    message = g_string_new ("Generated XML not like expected:\n\n");

    diff = test_util_diff_xml (expected_xml, generated_xml);
    g_string_append (message, diff);
    g_free (diff);

    g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, message->str);

    g_string_free (message, TRUE);
  }

  g_free (generated_xml);
}
