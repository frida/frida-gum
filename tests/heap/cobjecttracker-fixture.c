/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumcobjecttracker.h"

#ifdef G_OS_WIN32

#include "testutil.h"

#include <string.h>

#define COBJTRACKER_TESTCASE(NAME) \
    void test_cobject_tracker_ ## NAME (TestCObjectTrackerFixture * fixture, \
        gconstpointer data)
#define COBJTRACKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/CObjectTracker", test_cobject_tracker, \
        NAME, TestCObjectTrackerFixture)

typedef struct _MyObject MyObject;

GUM_NOINLINE static MyObject *
my_object_new (void)
{
  return (MyObject *) g_malloc (1);
}

GUM_NOINLINE static void
my_object_free (MyObject * obj)
{
  g_free (obj);
}

typedef struct _TestCObjectTrackerFixture
{
  GumCObjectTracker * tracker;
  GHashTable * ht1;
  GHashTable * ht2;
  MyObject * mo;
} TestCObjectTrackerFixture;

static void
test_cobject_tracker_fixture_create_tracker (
    TestCObjectTrackerFixture * fixture,
    GumBacktracer * backtracer)
{
  if (backtracer != NULL)
    fixture->tracker = gum_cobject_tracker_new_with_backtracer (backtracer);
  else
    fixture->tracker = gum_cobject_tracker_new ();

  gum_cobject_tracker_track (fixture->tracker,
      "GHashTable", g_hash_table_new_full);
  gum_cobject_tracker_track (fixture->tracker,
      "MyObject", my_object_new);

  gum_cobject_tracker_begin (fixture->tracker);
}

static void
test_cobject_tracker_fixture_enable_backtracer (
    TestCObjectTrackerFixture * fixture)
{
  GumBacktracer * backtracer;

  g_object_unref (fixture->tracker);

  backtracer = gum_backtracer_make_default ();
  test_cobject_tracker_fixture_create_tracker (fixture, backtracer);
  g_object_unref (backtracer);
}

static void
test_cobject_tracker_fixture_setup (TestCObjectTrackerFixture * fixture,
                                    gconstpointer data)
{
  test_cobject_tracker_fixture_create_tracker (fixture, NULL);
}

static void
test_cobject_tracker_fixture_teardown (TestCObjectTrackerFixture * fixture,
                                       gconstpointer data)
{
  if (fixture->ht1 != NULL)
    g_hash_table_unref (fixture->ht1);
  if (fixture->ht2 != NULL)
    g_hash_table_unref (fixture->ht2);
  if (fixture->mo != NULL)
    my_object_free (fixture->mo);
  g_object_unref (fixture->tracker);
}

#endif /* G_OS_WIN32 */
