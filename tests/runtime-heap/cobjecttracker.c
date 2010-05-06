/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include <string.h>
#include <gum/gum.h>

typedef struct _CObjectTrackerHarness CObjectTrackerHarness;
typedef struct _MyObject MyObject;

struct _CObjectTrackerHarness
{
  GumCObjectTracker * tracker;
  GHashTable * ht1;
  GHashTable * ht2;
  MyObject * mo;
};

static void cobject_tracker_harness_setup (CObjectTrackerHarness * h);
static void cobject_tracker_harness_setup_with_backtracer (
    CObjectTrackerHarness * h);
static void cobject_tracker_harness_setup_full (CObjectTrackerHarness * h,
    GumBacktracer * backtracer);
static void cobject_tracker_harness_teardown (CObjectTrackerHarness * h);
static MyObject * my_object_new (void);
static void my_object_free (MyObject * obj);

static void
test_total_count_increase (void)
{
  CObjectTrackerHarness h;

  cobject_tracker_harness_setup (&h);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 0);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "MyObject"), ==, 0);
  h.ht1 = g_hash_table_new (NULL, NULL);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 1);
  h.ht2 = g_hash_table_new (NULL, NULL);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 2);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 2);

  h.mo = my_object_new ();
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "MyObject"), ==, 1);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 3);

  cobject_tracker_harness_teardown (&h);
}

static void
test_total_count_decrease (void)
{
  CObjectTrackerHarness h;

  cobject_tracker_harness_setup (&h);

  h.ht1 = g_hash_table_new (NULL, NULL);
  h.ht2 = g_hash_table_new (NULL, NULL);
  h.mo = my_object_new ();

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 3);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 2);
  g_hash_table_unref (h.ht1); h.ht1 = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 1);
  g_hash_table_unref (h.ht2); h.ht2 = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "GHashTable"), ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 1);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "MyObject"), ==, 1);
  my_object_free (h.mo); h.mo = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      "MyObject"), ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (h.tracker,
      NULL), ==, 0);

  cobject_tracker_harness_teardown (&h);
}

static void
test_object_list (void)
{
  CObjectTrackerHarness h;
  GumList * cobjects, * walk;

  cobject_tracker_harness_setup_with_backtracer (&h);

  h.ht1 = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  h.mo = my_object_new ();

  cobjects = gum_cobject_tracker_peek_object_list (h.tracker);
  g_assert_cmpint (gum_list_length (cobjects), ==, 2);

  for (walk = cobjects; walk != NULL; walk = walk->next)
  {
    GumCObject * cobject = walk->data;

    g_assert (cobject->address == h.ht1 || cobject->address == h.mo);

    if (cobject->address == h.ht1)
      g_assert_cmpstr (cobject->type_name, ==, "GHashTable");
    else
      g_assert_cmpstr (cobject->type_name, ==, "MyObject");

    g_assert_cmpint (cobject->return_addresses.len, >=, 1);
    g_assert_cmpstr (cobject->return_addresses.items[0].function_name, ==,
        __FUNCTION__);
    g_assert_cmpint (cobject->return_addresses.items[0].line_number, >,
        0);
  }
  gum_cobject_list_free (cobjects);

  cobject_tracker_harness_teardown (&h);
}

static void
cobject_tracker_harness_setup (CObjectTrackerHarness * h)
{
  cobject_tracker_harness_setup_full (h, NULL);
}

static void
cobject_tracker_harness_setup_with_backtracer (CObjectTrackerHarness * h)
{
  GumBacktracer * backtracer;

#ifdef G_OS_WIN32
  backtracer = gum_windows_backtracer_new ();
#else
  backtracer = gum_gnu_backtracer_new ();
#endif
  cobject_tracker_harness_setup_full (h, backtracer);
  g_object_unref (backtracer);
}

static void
cobject_tracker_harness_setup_full (CObjectTrackerHarness * h,
                                    GumBacktracer * backtracer)
{
  memset (h, 0, sizeof (CObjectTrackerHarness));
  if (backtracer != NULL)
    h->tracker = gum_cobject_tracker_new_with_backtracer (backtracer);
  else
    h->tracker = gum_cobject_tracker_new ();
  gum_cobject_tracker_track (h->tracker, "GHashTable", g_hash_table_new_full);
  gum_cobject_tracker_track (h->tracker, "MyObject", my_object_new);
  gum_cobject_tracker_begin (h->tracker);
}

static void
cobject_tracker_harness_teardown (CObjectTrackerHarness * h)
{
  if (h->ht1 != NULL)
    g_hash_table_unref (h->ht1);
  if (h->ht2 != NULL)
    g_hash_table_unref (h->ht2);
  if (h->mo != NULL)
    my_object_free (h->mo);
  g_object_unref (h->tracker);
}

static MyObject *
my_object_new (void)
{
  return g_malloc (1);
}

static void
my_object_free (MyObject * obj)
{
  g_free (obj);
}

void
gum_test_register_cobject_tracker_tests (void)
{
  g_test_add_func ("/Gum/CObjectTracker/test-total-count-increase",
      &test_total_count_increase);
  g_test_add_func ("/Gum/CObjectTracker/test-total-count-decrease",
      &test_total_count_decrease);
  g_test_add_func ("/Gum/CObjectTracker/test-object-list",
      &test_object_list);
}
