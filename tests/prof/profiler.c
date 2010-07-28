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

#include "profilerharness.h"
#include "profilereportharness.h"

#include "lowlevel-helpers.h" /* for uninstrumentable function */
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sleepy_function (GumFakeSampler * sampler);
static void example_a (GumFakeSampler * sampler);
static void example_b (GumFakeSampler * sampler);
static void example_c (GumFakeSampler * sampler);
static void example_d (GumFakeSampler * sampler);
static void example_e (GumFakeSampler * sampler);
static void example_f (GumFakeSampler * sampler);
static void example_g (GumFakeSampler * sampler);
static void example_cyclic_a (GumFakeSampler * sampler, gint flag);
static void example_cyclic_b (GumFakeSampler * sampler, gint flag);
static gboolean exclude_simple_stdcall_50 (const gchar * match);
static void GUM_CDECL simple_cdecl_42 (GumFakeSampler * sampler);
static void GUM_STDCALL simple_stdcall_48 (GumFakeSampler * sampler);
static void GUM_STDCALL simple_stdcall_50 (GumFakeSampler * sampler);
static void recursive_function (gint count);
static void deep_recursive_function (gint count);
static void deep_recursive_caller (gint count);
#ifdef G_OS_WIN32
static void spin_for_one_tenth_second (void);
#endif
static void example_a_calls_b_thrice (GumFakeSampler * sampler);
static void example_b_dynamic (GumFakeSampler * sampler, guint cost);
static void example_worst_case_info (GumFakeSampler * sampler, GumSample cost,
    const gchar * magic);
static void example_worst_case_recursive (gint count,
    GumFakeSampler * sampler);
static void inspect_worst_case_info (GumInvocationContext * context,
    gchar * output_buf, guint output_buf_len);
static void inspect_recursive_worst_case_info (GumInvocationContext * context,
    gchar * output_buf, guint output_buf_len);
static void simple_1 (GumFakeSampler * sampler);
static void simple_2 (GumFakeSampler * sampler);
static void simple_3 (GumFakeSampler * sampler);

static void
test_i_can_has_instrumentability (void)
{
  ProfilerHarness h;
  UnsupportedFunction * unsupported_functions;
  guint count;

  profiler_harness_setup (&h);
  unsupported_functions = unsupported_function_list_new (&count);

  g_assert_cmpint (gum_profiler_instrument_function (h.profiler,
      unsupported_functions[0].code, h.sampler), ==,
      GUM_INSTRUMENT_WRONG_SIGNATURE);

  unsupported_function_list_free (unsupported_functions);
  profiler_harness_teardown (&h);
}

static void
test_already_instrumented (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  g_assert_cmpint (gum_profiler_instrument_function (h.profiler,
      &sleepy_function, h.sampler), ==, GUM_INSTRUMENT_OK);
  g_assert_cmpint (gum_profiler_instrument_function (h.profiler,
      &sleepy_function, h.sampler), ==, GUM_INSTRUMENT_WAS_INSTRUMENTED);

  profiler_harness_teardown (&h);
}

static void
test_flat_function (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  g_assert_cmpint (gum_profiler_instrument_function (h.profiler,
      &sleepy_function, h.sampler), ==, GUM_INSTRUMENT_OK);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (h.profiler), ==, 0);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &sleepy_function), ==, 0);

  sleepy_function (h.fake_sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (h.profiler), ==, 1);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &sleepy_function), ==, 1000);

  profiler_harness_teardown (&h);
}

static void
test_two_calls (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function (h.profiler, &sleepy_function, h.sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (h.profiler), ==, 0);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &sleepy_function), ==, 0);

  sleepy_function (h.fake_sampler);
  sleepy_function (h.fake_sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (h.profiler), ==, 1);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &sleepy_function), ==, 2 * 1000);

  profiler_harness_teardown (&h);
}

static void
test_report_bottleneck (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_a (h.fake_sampler);
  profile_report_harness_assert_n_top_nodes (&h, 1, "example_a", "example_c");

  profile_report_harness_teardown (&h);
}

static void
test_report_bottlenecks (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_a (h.fake_sampler);
  example_d (h.fake_sampler);

  profile_report_harness_assert_n_top_nodes (&h, 2,
      "example_d", "example_c",
      "example_a", "example_c");

  profile_report_harness_teardown (&h);
}

static void
test_report_child_depth (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_e (h.fake_sampler);

  profile_report_harness_assert_n_top_nodes (&h, 1, "example_e", "example_f");
  profile_report_harness_assert_depth_from_root_node (&h, 0, "example_e",
      "example_f", "example_g", NULL);

  profile_report_harness_teardown (&h);
}

static void
test_report_cyclic_recursion (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_cyclic_a (h.fake_sampler, 1);

  profile_report_harness_assert_n_top_nodes (&h, 1, "example_cyclic_a",
      "example_cyclic_b");
  profile_report_harness_assert_depth_from_root_node (&h, 0,
      "example_cyclic_a", "example_cyclic_b", NULL);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &example_cyclic_a), ==, 4);

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_basic (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_a (h.fake_sampler);

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_a\" total_calls=\"1\" total_duration=\"9\">"
            "<WorstCase duration=\"9\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_loop (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_cyclic_a (h.fake_sampler, 1);

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_cyclic_a\" total_calls=\"2\" total_duration=\"4\">"
            "<WorstCase duration=\"4\"></WorstCase>"
            "<Node name=\"example_cyclic_b\" total_calls=\"1\" total_duration=\"3\">"
              "<WorstCase duration=\"3\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_loop_implicit (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_cyclic_a (h.fake_sampler, 1);
  example_cyclic_b (h.fake_sampler, 0);

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_cyclic_b\" total_calls=\"2\" total_duration=\"6\">"
            "<WorstCase duration=\"3\"></WorstCase>"
            "<Node name=\"example_cyclic_a\" total_calls=\"3\" total_duration=\"5\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
          "<Node name=\"example_cyclic_a\" total_calls=\"3\" total_duration=\"5\">"
            "<WorstCase duration=\"4\"></WorstCase>"
            "<Node name=\"example_cyclic_b\" total_calls=\"2\" total_duration=\"6\">"
              "<WorstCase duration=\"3\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_multiple_threads (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup (&h);

  example_a (h.fake_sampler);
  g_thread_join (g_thread_create ((GThreadFunc) example_d, h.fake_sampler,
      TRUE, NULL));

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_d\" total_calls=\"1\" total_duration=\"11\">"
            "<WorstCase duration=\"11\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"example_a\" total_calls=\"1\" total_duration=\"9\">"
            "<WorstCase duration=\"9\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_worse_case_info (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup_full (&h, NULL);

  gum_profiler_instrument_function_with_inspector (h.profiler,
      &example_worst_case_info, h.sampler, inspect_worst_case_info);

  example_worst_case_info (h.fake_sampler, 1, "early");
  example_worst_case_info (h.fake_sampler, 3, "mid");
  example_worst_case_info (h.fake_sampler, 2, "late");

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_worst_case_info\" total_calls=\"3\" total_duration=\"6\">"
            "<WorstCase duration=\"3\">mid</WorstCase>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_report_xml_thread_ordering (void)
{
  ProfileReportHarness h;

  profile_report_harness_setup_full (&h, NULL);

  gum_profiler_instrument_functions_matching (h.profiler, "simple_*",
      h.sampler, NULL);

  simple_1 (h.fake_sampler);
  g_thread_join (g_thread_create ((GThreadFunc) simple_2, h.fake_sampler, TRUE,
      NULL));
  g_thread_join (g_thread_create ((GThreadFunc) simple_3, h.fake_sampler, TRUE,
      NULL));

  profile_report_harness_assert_same_xml (&h,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"simple_3\" total_calls=\"1\" total_duration=\"3\">"
            "<WorstCase duration=\"3\"></WorstCase>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"simple_2\" total_calls=\"1\" total_duration=\"2\">"
            "<WorstCase duration=\"2\"></WorstCase>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"simple_1\" total_calls=\"1\" total_duration=\"1\">"
            "<WorstCase duration=\"1\"></WorstCase>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");

  profile_report_harness_teardown (&h);
}

static void
test_profile_matching_functions (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_functions_matching (h.profiler, "simple_*",
      h.sampler, exclude_simple_stdcall_50);

  simple_cdecl_42 (h.fake_sampler);
  simple_stdcall_48 (h.fake_sampler);
  simple_stdcall_50 (h.fake_sampler);

  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &simple_cdecl_42), ==, 42);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &simple_stdcall_48), ==, 48);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (h.profiler, 0,
      &simple_stdcall_50), ==, 0);

  profiler_harness_teardown (&h);
}

static void
test_recursion (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function (h.profiler, &recursive_function,
      h.sampler);
  recursive_function (2);

  profiler_harness_teardown (&h);
}

static void
test_deep_recursion (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function (h.profiler, &deep_recursive_function,
      h.sampler);
  gum_profiler_instrument_function (h.profiler, &deep_recursive_caller,
      h.sampler);
  deep_recursive_function (3);

  profiler_harness_teardown (&h);
}

static void
test_worst_case_duration (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function (h.profiler, &example_a_calls_b_thrice,
      h.sampler);
  gum_profiler_instrument_function (h.profiler, &example_b_dynamic,
      h.sampler);

  g_assert_cmpuint (gum_profiler_get_worst_case_duration_of (h.profiler, 0,
      &example_b_dynamic), ==, 0);

  example_a_calls_b_thrice (h.fake_sampler);

  g_assert_cmpuint (gum_profiler_get_worst_case_duration_of (h.profiler, 0,
      &example_b_dynamic), ==, 3);

  profiler_harness_teardown (&h);
}

static void
test_worst_case_info (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function_with_inspector (h.profiler,
      &example_worst_case_info, h.sampler, inspect_worst_case_info);

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (h.profiler, 0,
      &example_worst_case_info), ==, "");

  example_worst_case_info (h.fake_sampler, 1, "early");
  example_worst_case_info (h.fake_sampler, 3, "mid");
  example_worst_case_info (h.fake_sampler, 2, "late");

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (h.profiler, 0,
      &example_worst_case_info), ==, "mid");

  profiler_harness_teardown (&h);
}

static void
test_worst_case_info_on_recursion (void)
{
  ProfilerHarness h;

  profiler_harness_setup (&h);

  gum_profiler_instrument_function_with_inspector (h.profiler,
      &example_worst_case_recursive, h.sampler,
      inspect_recursive_worst_case_info);

  example_worst_case_recursive (2, h.fake_sampler);

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (h.profiler, 0,
      &example_worst_case_recursive), ==, "2");

  profiler_harness_teardown (&h);
}

static void GUM_NOINLINE
sleepy_function (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1000);
}

static void GUM_NOINLINE
example_a (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 2);
  example_c (sampler);
  example_b (sampler);
}

static void GUM_NOINLINE
example_b (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);
}

static void GUM_NOINLINE
example_c (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 4);
}

static void GUM_NOINLINE
example_d (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 7);
  example_c (sampler);
}

static void GUM_NOINLINE
example_e (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);
  example_f (sampler);
}

static void GUM_NOINLINE
example_f (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 4);
  example_g (sampler);
}

static void GUM_NOINLINE
example_g (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 5);
}

static void GUM_NOINLINE
example_cyclic_a (GumFakeSampler * sampler,
                  gint flag)
{
  gum_fake_sampler_advance (sampler, 1);

  if (flag)
    example_cyclic_b (sampler, 0);
}

static void GUM_NOINLINE
example_cyclic_b (GumFakeSampler * sampler,
                  gint flag)
{
  gum_fake_sampler_advance (sampler, 2);
  example_cyclic_a (sampler, flag);
}

static gboolean
exclude_simple_stdcall_50 (const gchar * match)
{
  return strcmp (match, "simple_stdcall_50") != 0;
}

static void GUM_NOINLINE GUM_CDECL
simple_cdecl_42 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 42);
}

static void GUM_NOINLINE GUM_STDCALL
simple_stdcall_48 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 48);
}

static void GUM_NOINLINE GUM_STDCALL
simple_stdcall_50 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 50);
}

static void
recursive_function (gint count)
{
  if (--count > 0)
    recursive_function (count);
}

static void
deep_recursive_function (gint count)
{
  if (--count > 0)
  {
    deep_recursive_function (count);
    deep_recursive_caller (count);
  }
}

static void
deep_recursive_caller (gint count)
{
  if (count == 1)
    deep_recursive_function (count);
}

#ifdef G_OS_WIN32
static void
spin_for_one_tenth_second (void)
{
  GTimer * timer;
  guint i;
  guint b = 0;

  timer = g_timer_new ();

  do
  {
    for (i = 0; i < 1000000; i++)
      b += i * i;
  }
  while (g_timer_elapsed (timer, NULL) < 0.1);

  g_timer_destroy (timer);
}
#endif

gint dummy_variable_to_trick_optimizer = 0;

static void GUM_NOINLINE
example_a_calls_b_thrice (GumFakeSampler * sampler)
{
  example_b_dynamic (sampler, 1);
  example_b_dynamic (sampler, 3);
  example_b_dynamic (sampler, 2);
}

static void GUM_NOINLINE
example_b_dynamic (GumFakeSampler * sampler,
                   guint cost)
{
  gum_fake_sampler_advance (sampler, cost);
}

static void GUM_NOINLINE
example_worst_case_info (GumFakeSampler * sampler,
                         GumSample cost,
                         const gchar * magic)
{
  gum_fake_sampler_advance (sampler, cost);
}

static void GUM_NOINLINE
example_worst_case_recursive (gint count,
                              GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1);

  if (count > 0)
    example_worst_case_recursive (count - 1, sampler);
}

static void
inspect_worst_case_info (GumInvocationContext * context,
                         gchar * output_buf,
                         guint output_buf_len)
{
  const gchar * magic;

  magic = (gchar *) gum_invocation_context_get_nth_argument (context, 2);

#ifdef _MSC_VER
  strcpy_s (output_buf, output_buf_len, magic);
#else
  strcpy (output_buf, magic);
#endif
}

static void
inspect_recursive_worst_case_info (GumInvocationContext * context,
                                   gchar * output_buf,
                                   guint output_buf_len)
{
  gint count;

  count = (gint) gum_invocation_context_get_nth_argument (context, 0);

#ifdef _MSC_VER
  sprintf_s (output_buf, output_buf_len, "%d", count);
#else
  sprintf (output_buf, "%d", count);
#endif
}

/* These three should be kept in this order to make the function addresses
 * non-consecutive... */

static void GUM_NOINLINE
simple_2 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 2);
}

static void GUM_NOINLINE
simple_1 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1);
}

static void GUM_NOINLINE
simple_3 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);
}

void
gum_test_register_profiler_tests (void)
{
  g_test_add_func ("/Gum/Profiler/test-i-can-has-instrumentability",
      &test_i_can_has_instrumentability);
  g_test_add_func ("/Gum/Profiler/test-already-instrumented",
      &test_already_instrumented);

  g_test_add_func ("/Gum/Profiler/test-flat-function", &test_flat_function);
  g_test_add_func ("/Gum/Profiler/test-two-calls", &test_two_calls);
  g_test_add_func ("/Gum/Profiler/test-matching-functions",
      &test_profile_matching_functions);
  g_test_add_func ("/Gum/Profiler/test-recursion", &test_recursion);
  g_test_add_func ("/Gum/Profiler/test-deep-recursion", &test_deep_recursion);
  g_test_add_func ("/Gum/Profiler/test-worst-case-duration",
      &test_worst_case_duration);
  g_test_add_func ("/Gum/Profiler/test-worst-case-info",
      &test_worst_case_info);
  g_test_add_func ("/Gum/Profiler/test-worst-case-info-on-recursion",
      &test_worst_case_info_on_recursion);

  g_test_add_func ("/Gum/Profiler/Report/test-bottleneck",
      &test_report_bottleneck);
  g_test_add_func ("/Gum/Profiler/Report/test-bottlenecks",
      &test_report_bottlenecks);
  g_test_add_func ("/Gum/Profiler/Report/test-child-depth",
      &test_report_child_depth);
  g_test_add_func ("/Gum/Profiler/Report/test-cyclic-recursion",
      &test_report_cyclic_recursion);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-basic",
      &test_report_xml_basic);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-loop",
      &test_report_xml_loop);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-loop-implicit",
      &test_report_xml_loop_implicit);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-multiple-threads",
      &test_report_xml_multiple_threads);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-worst-case-info",
      &test_report_xml_worse_case_info);
  g_test_add_func ("/Gum/Profiler/Report/test-xml-thread-ordering",
      &test_report_xml_thread_ordering);
}
