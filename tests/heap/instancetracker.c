/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "instancetracker-fixture.c"

TEST_LIST_BEGIN (instancetracker)
  INSTRACKER_TESTENTRY (total_count)
  INSTRACKER_TESTENTRY (type_filter_function)
  INSTRACKER_TESTENTRY (nested_trackers)
  INSTRACKER_TESTENTRY (ignore_other_trackers)
  INSTRACKER_TESTENTRY (stale_instances)
  INSTRACKER_TESTENTRY (avoid_heap)
TEST_LIST_END ()

static gboolean no_ponies_filter_func (GumInstanceTracker * tracker,
    GType gtype, gpointer user_data);

INSTRACKER_TESTCASE (total_count)
{
  GumInstanceTracker * t = fixture->tracker;
  ZooZebra * zebra;
  MyPony * pony1, * pony2;

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
}

INSTRACKER_TESTCASE (type_filter_function)
{
  GumInstanceTracker * t = fixture->tracker;
  MyPony * pony;
  ZooZebra * zebra;
  guint counter = 0;

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
}

INSTRACKER_TESTCASE (nested_trackers)
{
  GumInstanceTracker * t1 = fixture->tracker;
  GumInstanceTracker * t2 = NULL;
  MyPony * pony1, * pony2;

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
}

INSTRACKER_TESTCASE (ignore_other_trackers)
{
  GumInstanceTracker * t1 = fixture->tracker;
  GumInstanceTracker * t2;

  t2 = gum_instance_tracker_new ();
  g_assert_cmpuint (gum_instance_tracker_peek_total_count (t1, NULL), ==, 0);
  g_object_unref (t2);
}

INSTRACKER_TESTCASE (stale_instances)
{
  GumInstanceTracker * t = fixture->tracker;
  MyPony * pony1, * pony2, * pony3;
  GumList * stale, * cur;

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
}

INSTRACKER_TESTCASE (avoid_heap)
{
  GumInstanceTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  GumList * stale;

  heap_access_counter = heap_access_counter_new ();

  gum_instance_tracker_add_instance (t, GUINT_TO_POINTER (0xbadf00d),
      G_TYPE_OBJECT);
  stale = gum_instance_tracker_peek_stale (t);
  gum_list_free (stale);

  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);

  g_object_unref (heap_access_counter);
}

static gboolean
no_ponies_filter_func (GumInstanceTracker * tracker,
                       GType gtype,
                       gpointer user_data)
{
  guint * counter = (guint *) user_data;
  (*counter)++;
  return gtype != MY_TYPE_PONY;
}
