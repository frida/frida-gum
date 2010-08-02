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

#include <string.h>

TEST_LIST_BEGIN (instancetracker)
  INSTRACKER_TESTENTRY (total_count)
  INSTRACKER_TESTENTRY (type_filter_function)
  INSTRACKER_TESTENTRY (nested_trackers)
  INSTRACKER_TESTENTRY (ignore_other_trackers)
  INSTRACKER_TESTENTRY (peek_instances)
  INSTRACKER_TESTENTRY (walk_instances)
  INSTRACKER_TESTENTRY (avoid_heap)
TEST_LIST_END ()

typedef struct _WalkInstancesContext WalkInstancesContext;

struct _WalkInstancesContext
{
  GSList * expected_instances;
  guint call_count;
};

static gboolean no_ponies_filter_func (GumInstanceTracker * tracker,
    GType gtype, gpointer user_data);
static void walk_instance (GumInstanceDetails * id, gpointer user_data);

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
  gum_instance_tracker_begin (t2, NULL);

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

INSTRACKER_TESTCASE (peek_instances)
{
  GumInstanceTracker * t = fixture->tracker;
  MyPony * pony1, * pony2, * pony3;
  GumList * instances, * cur;

  g_test_message ("Should not be any instances around yet");
  g_assert (gum_instance_tracker_peek_instances (t) == NULL);

  pony1 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  pony2 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  pony3 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));

  instances = gum_instance_tracker_peek_instances (t);
  g_test_message ("We should now have three instances");
  g_assert (instances != NULL);
  g_assert_cmpuint (gum_list_length (instances), ==, 3);

  g_test_message ("The instances should be our ponies");
  for (cur = instances; cur != NULL; cur = cur->next)
    g_assert (cur->data == pony1 || cur->data == pony2 || cur->data == pony3);

  gum_list_free (instances); instances = NULL;

  g_object_unref (pony2);

  instances = gum_instance_tracker_peek_instances (t);
  g_test_message ("We should now have two instances");
  g_assert (instances != NULL);
  g_assert_cmpuint (gum_list_length (instances), ==, 2);

  g_test_message ("Only pony1 and pony3 should be left now");
  for (cur = instances; cur != NULL; cur = cur->next)
    g_assert (cur->data == pony1 || cur->data == pony3);

  gum_list_free (instances); instances = NULL;

  g_object_unref (pony1);
  g_object_unref (pony3);
}

INSTRACKER_TESTCASE (walk_instances)
{
  GumInstanceTracker * t = fixture->tracker;
  WalkInstancesContext ctx;
  MyPony * pony1, * pony2, * pony3;

  ctx.call_count = 0;
  ctx.expected_instances = NULL;

  g_test_message ("Should not be any instances around yet");
  gum_instance_tracker_walk_instances (t, walk_instance, &ctx);

  pony1 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  ctx.expected_instances = g_slist_prepend (ctx.expected_instances, pony1);
  pony2 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  ctx.expected_instances = g_slist_prepend (ctx.expected_instances, pony2);
  pony3 = MY_PONY (g_object_new (MY_TYPE_PONY, NULL));
  ctx.expected_instances = g_slist_prepend (ctx.expected_instances, pony3);

  g_test_message ("We should now have three instances");
  gum_instance_tracker_walk_instances (t, walk_instance, &ctx);
  g_assert_cmpuint (ctx.call_count, ==, 3);

  g_object_unref (pony2);

  g_test_message ("We should now have two instances");
  ctx.call_count = 0;
  ctx.expected_instances = g_slist_remove (ctx.expected_instances, pony2);
  gum_instance_tracker_walk_instances (t, walk_instance, &ctx);
  g_assert_cmpuint (ctx.call_count, ==, 2);

  g_object_unref (pony1);
  g_object_unref (pony3);

  g_slist_free (ctx.expected_instances);
}

INSTRACKER_TESTCASE (avoid_heap)
{
  GumInstanceTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  GumList * instances;

  heap_access_counter = heap_access_counter_new ();

  gum_instance_tracker_add_instance (t, GUINT_TO_POINTER (0xbadf00d),
      G_TYPE_OBJECT);
  instances = gum_instance_tracker_peek_instances (t);
  gum_list_free (instances);

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

static void
walk_instance (GumInstanceDetails * id, gpointer user_data)
{
  WalkInstancesContext * ctx = (WalkInstancesContext *) user_data;
  GSList * entry;
  const GTypeInstance * expected_instance, * cur_instance;
  GType type;

  entry = g_slist_find (ctx->expected_instances, id->address);
  g_assert (entry != NULL);
  expected_instance = (const GTypeInstance *) entry->data;
  cur_instance = (const GTypeInstance *) id->address;
  g_assert (cur_instance == expected_instance);
  g_assert_cmpuint (id->ref_count,
      ==, G_OBJECT (expected_instance)->ref_count);
  g_assert_cmpint (strcmp (id->type_name,
      g_type_name (G_TYPE_FROM_INSTANCE (expected_instance))), ==, 0);

  ctx->call_count++;
}
