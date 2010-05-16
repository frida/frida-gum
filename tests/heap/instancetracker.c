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

#include <gum/gum.h>
#include "dummyclasses.h"
#include "testutil.h"

static gboolean no_ponies_filter_func (GumInstanceTracker * tracker,
    GType gtype, gpointer user_data);

static void
test_total_count (void)
{
  GumInstanceTracker * t;
  ZooZebra * zebra;
  MyPony * pony1, * pony2;

  t = gum_instance_tracker_new ();

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL), ==, 0);

  zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL), ==, 1);

  pony1 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL), ==, 2);

  pony2 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL), ==, 3);

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "ZooZebra"),
      ==, 1);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "MyPony"),
      ==, 2);

  g_object_unref (pony2);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "MyPony"),
      ==, 1);

  g_object_unref (pony1);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "MyPony"),
      ==, 0);

  g_object_unref (zebra);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "ZooZebra"),
      ==, 0);

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL), ==, 0);

  g_object_unref (t);
}

static void
test_type_filter_function (void)
{
  GumInstanceTracker * t;
  MyPony * pony;
  ZooZebra * zebra;
  guint counter = 0;

  t = gum_instance_tracker_new ();

  gum_instance_tracker_set_type_filter_function (t, no_ponies_filter_func,
      &counter);

  pony = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL),
      ==, 0);

  zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, NULL),
      ==, 1);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t, "ZooZebra"),
      ==, 1);

  g_assert_cmpint (counter, ==, 2);

  g_object_unref (zebra);
  g_object_unref (pony);

  g_object_unref (t);
}

static void
test_nested_trackers (void)
{
  GumInstanceTracker * t1, * t2;
  MyPony * pony1, * pony2;

  t1 = gum_instance_tracker_new ();

  pony1 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, "MyPony"),
      ==, 1);

  t2 = gum_instance_tracker_new ();

  pony2 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t2, "MyPony"),
      ==, 1);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, "MyPony"),
      ==, 2);

  g_object_unref (pony1);

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t2, "MyPony"),
      ==, 1);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, "MyPony"),
      ==, 1);

  g_object_unref (pony2);

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t2, "MyPony"),
      ==, 0);
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, "MyPony"),
      ==, 0);

  g_object_unref (t2);
  g_object_unref (t1);
}

static void
test_ignore_other_trackers (void)
{
  GumInstanceTracker * t1, * t2;

  t1 = gum_instance_tracker_new ();
  t2 = gum_instance_tracker_new ();

  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, NULL), ==, 0);

  g_object_unref (t2);
  g_object_unref (t1);
}

static void
test_stale_instances (void)
{
  GumInstanceTracker * t;
  MyPony * pony1, * pony2, * pony3;
  GumList * stale, * cur;

  t = gum_instance_tracker_new ();

  g_test_message ("Should not be any stale instances around yet");
  g_assert (gum_instance_tracker_peek_stale (t) == NULL);

  pony1 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  pony2 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  pony3 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));

  stale = gum_instance_tracker_peek_stale (t);
  g_test_message ("We should now have three stale instances");
  g_assert (stale != NULL);
  g_assert_cmpuint (gum_list_length (stale), ==, 3);

  g_test_message ("The stale instances should be our ponies");
  for (cur = stale; cur != NULL; cur = cur->next)
    g_assert (cur->data == pony1 || cur->data == pony2 || cur->data == pony3);

  gum_list_free (stale); stale = NULL;

  g_object_unref (pony2);

  stale = gum_instance_tracker_peek_stale (t);
  g_test_message ("We should now have two stale instances");
  g_assert (stale != NULL);
  g_assert_cmpuint (gum_list_length (stale), ==, 2);

  g_test_message ("Only pony1 and pony3 should be left stale now");
  for (cur = stale; cur != NULL; cur = cur->next)
    g_assert (cur->data == pony1 || cur->data == pony3);

  gum_list_free (stale); stale = NULL;

  g_object_unref (pony1);
  g_object_unref (pony3);

  g_object_unref (t);
}

static void
test_avoid_heap (void)
{
  GumInstanceTracker * t;
  GumSampler * heap_access_counter;
  GumList * stale;

  t = gum_instance_tracker_new ();
  heap_access_counter = heap_access_counter_new ();

  gum_instance_tracker_add_instance (t, GUINT_TO_POINTER (0xbadf00d),
      G_TYPE_OBJECT);
  stale = gum_instance_tracker_peek_stale (t);
  gum_list_free (stale);

  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);

  g_object_unref (heap_access_counter);
  g_object_unref (t);
}

static gboolean
no_ponies_filter_func (GumInstanceTracker * tracker,
                       GType gtype,
                       gpointer user_data)
{
  guint * counter = user_data;
  (*counter)++;
  return gtype != MY_TYPE_PONY;
}

void
gum_test_register_instance_tracker_tests (void)
{
  g_test_add_func ("/Gum/InstanceTracker/test-total-count",
      &test_total_count);
  g_test_add_func ("/Gum/InstanceTracker/test-type-filter-function",
      &test_type_filter_function);
  g_test_add_func ("/Gum/InstanceTracker/test-nested-trackers",
      &test_nested_trackers);
  g_test_add_func ("/Gum/InstanceTracker/test-ignore-other-trackers",
      &test_ignore_other_trackers);
  g_test_add_func ("/Gum/InstanceTracker/test-stale-instances",
      &test_stale_instances);
  g_test_add_func ("/Gum/InstanceTracker/PrivateHeap/test-avoid-heap",
      &test_avoid_heap);
}
