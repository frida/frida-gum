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

#include "cobjecttracker-fixture.c"

#ifdef G_OS_WIN32

TEST_LIST_BEGIN (cobjecttracker)
  COBJTRACKER_TESTENTRY (total_count_increase)
  COBJTRACKER_TESTENTRY (total_count_decrease)
  COBJTRACKER_TESTENTRY (object_list)
TEST_LIST_END ()

COBJTRACKER_TESTCASE (total_count_increase)
{
  GumCObjectTracker * t = fixture->tracker;

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 0);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "MyObject"),
      ==, 0);
  fixture->ht1 = g_hash_table_new (NULL, NULL);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 1);
  fixture->ht2 = g_hash_table_new (NULL, NULL);
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 2);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 2);

  fixture->mo = my_object_new ();
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "MyObject"),
      ==, 1);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 3);
}

COBJTRACKER_TESTCASE (total_count_decrease)
{
  GumCObjectTracker * t = fixture->tracker;

  fixture->ht1 = g_hash_table_new (NULL, NULL);
  fixture->ht2 = g_hash_table_new (NULL, NULL);
  fixture->mo = my_object_new ();

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 3);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 2);
  g_hash_table_unref (fixture->ht1); fixture->ht1 = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 1);
  g_hash_table_unref (fixture->ht2); fixture->ht2 = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "GHashTable"),
      ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 1);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "MyObject"),
      ==, 1);
  my_object_free (fixture->mo); fixture->mo = NULL;
  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, "MyObject"),
      ==, 0);

  g_assert_cmpuint (gum_cobject_tracker_peek_total_count (t, NULL), ==, 0);
}

COBJTRACKER_TESTCASE (object_list)
{
  GumList * cobjects, * walk;

  test_cobject_tracker_fixture_enable_backtracer (fixture);

  fixture->ht1 = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  fixture->mo = my_object_new ();

  cobjects = gum_cobject_tracker_peek_object_list (fixture->tracker);
  g_assert_cmpint (gum_list_length (cobjects), ==, 2);

  for (walk = cobjects; walk != NULL; walk = walk->next)
  {
    GumCObject * cobject = (GumCObject *) walk->data;

    g_assert (cobject->address == fixture->ht1 ||
        cobject->address == fixture->mo);

    if (cobject->address == fixture->ht1)
      g_assert_cmpstr (cobject->type_name, ==, "GHashTable");
    else
      g_assert_cmpstr (cobject->type_name, ==, "MyObject");

    {
#ifdef G_OS_WIN32
      GumReturnAddressDetails rad;

      g_assert (gum_return_address_details_from_address (
          cobject->return_addresses.items[0], &rad));
      g_assert_cmpstr (rad.function_name, ==, __FUNCTION__);
      g_assert_cmpint (rad.line_number, >, 0);
#else
      g_assert (cobject->return_addresses.items[0] != NULL);
#endif
    }
  }

  gum_cobject_list_free (cobjects);
}

#endif /* G_OS_WIN32 */
