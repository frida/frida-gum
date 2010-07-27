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

#include "allocationtracker-fixture.c"

TEST_LIST_BEGIN (allocation_tracker)
  ALLOCTRACKER_TESTENTRY (begin)
  ALLOCTRACKER_TESTENTRY (end)

  ALLOCTRACKER_TESTENTRY (block_count)
  ALLOCTRACKER_TESTENTRY (block_total_size)
  ALLOCTRACKER_TESTENTRY (block_list_pointers)
  ALLOCTRACKER_TESTENTRY (block_list_sizes)
  ALLOCTRACKER_TESTENTRY (block_list_backtraces)
  ALLOCTRACKER_TESTENTRY (block_groups)

  ALLOCTRACKER_TESTENTRY (filter_function)

  ALLOCTRACKER_TESTENTRY (realloc_new_block)
  ALLOCTRACKER_TESTENTRY (realloc_unknown_block)
  ALLOCTRACKER_TESTENTRY (realloc_zero_size)
  ALLOCTRACKER_TESTENTRY (realloc_backtrace)

  ALLOCTRACKER_TESTENTRY (backtracer_gtype_interop)

#if 0
  ALLOCTRACKER_TESTENTRY (avoid_heap_priv)
  ALLOCTRACKER_TESTENTRY (avoid_heap_public)
  ALLOCTRACKER_TESTENTRY (hashtable_resize)
  ALLOCTRACKER_TESTENTRY (hashtable_life)
#endif
TEST_LIST_END ()

static gboolean filter_cb (GumAllocationTracker * tracker, gpointer address,
    guint size, gpointer user_data);

ALLOCTRACKER_TESTCASE (begin)
{
  GumAllocationTracker * t = fixture->tracker;
  GumList * blocks, * groups;

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
  g_assert (gum_allocation_tracker_peek_block_list (t) == NULL);
  g_assert (gum_allocation_tracker_peek_block_groups (t) == NULL);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 123);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
  g_assert (gum_allocation_tracker_peek_block_list (t) == NULL);
  g_assert (gum_allocation_tracker_peek_block_groups (t) == NULL);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 321);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 321);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (gum_list_length (blocks), ==, 1);
  gum_allocation_block_list_free (blocks);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (gum_list_length (groups), ==, 1);
  gum_allocation_group_list_free (groups);
}

ALLOCTRACKER_TESTCASE (end)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 321);
  gum_allocation_tracker_end (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 313);

  g_assert (gum_allocation_tracker_peek_block_list (t) == NULL);
  g_assert (gum_allocation_tracker_peek_block_groups (t) == NULL);

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
}

ALLOCTRACKER_TESTCASE (block_count)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 84);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

ALLOCTRACKER_TESTCASE (block_total_size)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 31);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 31);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 19);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 50);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 81);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 100);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 19);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
}

ALLOCTRACKER_TESTCASE (block_list_pointers)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 24);

  {
    GumList * blocks, * cur;

    blocks = gum_allocation_tracker_peek_block_list (t);
    g_assert_cmpuint (gum_list_length (blocks), ==, 2);

    for (cur = blocks; cur != NULL; cur = cur->next)
    {
      GumAllocationBlock * block = cur->data;
      g_assert (block->address == DUMMY_BLOCK_A ||
          block->address == DUMMY_BLOCK_B);
    }

    gum_allocation_block_list_free (blocks);
  }

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);

  {
    GumList * blocks;
    GumAllocationBlock * block;

    blocks = gum_allocation_tracker_peek_block_list (t);
    g_assert_cmpuint (gum_list_length (blocks), ==, 1);

    block = blocks->data;
    g_assert (block->address == DUMMY_BLOCK_B);

    gum_allocation_block_list_free (blocks);
  }

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
}

ALLOCTRACKER_TESTCASE (block_list_sizes)
{
  GumAllocationTracker * t = fixture->tracker;
  GumList * blocks, * cur;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 24);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (gum_list_length (blocks), ==, 2);

  for (cur = blocks; cur != NULL; cur = cur->next)
  {
    GumAllocationBlock * block = cur->data;

    if (block->address == DUMMY_BLOCK_A)
      g_assert_cmpuint (block->size, ==, 42);
    else if (block->address == DUMMY_BLOCK_B)
      g_assert_cmpuint (block->size, ==, 24);
    else
      g_assert_not_reached ();
  }

  gum_allocation_block_list_free (blocks);
}

ALLOCTRACKER_TESTCASE (block_list_backtraces)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  GumList * blocks;
  GumAllocationBlock * block;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (gum_list_length (blocks), ==, 1);

  block = (GumAllocationBlock *) blocks->data;
  g_assert (block->address == DUMMY_BLOCK_A);

  g_assert_cmpuint (block->return_addresses.len, ==, 2);

  g_assert (gum_return_address_is_equal (&block->return_addresses.items[0],
      &dummy_return_addresses_a[0]));

  g_assert (gum_return_address_is_equal (&block->return_addresses.items[1],
      &dummy_return_addresses_a[1]));

  gum_allocation_block_list_free (blocks);

  g_object_unref (t);
  g_object_unref (backtracer);
}

ALLOCTRACKER_TESTCASE (block_groups)
{
  GumAllocationTracker * t = fixture->tracker;
  GumList * groups, * cur;

  gum_allocation_tracker_begin (t);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (gum_list_length (groups), ==, 0);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_C, 42);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_C);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_C, 42);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_C);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_D, 1337);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_E, 1000);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_E);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (gum_list_length (groups), ==, 3);

  for (cur = groups; cur != NULL; cur = cur->next)
  {
    GumAllocationGroup * group = (GumAllocationGroup *) cur->data;

    if (group->size == 42)
    {
      g_assert_cmpuint (group->alive_now, ==, 1);
      g_assert_cmpuint (group->alive_peak, ==, 3);
      g_assert_cmpuint (group->total_peak, ==, 4);
    }
    else if (group->size == 1000)
    {
      g_assert_cmpuint (group->alive_now, ==, 0);
      g_assert_cmpuint (group->alive_peak, ==, 1);
      g_assert_cmpuint (group->total_peak, ==, 1);
    }
    else if (group->size == 1337)
    {
      g_assert_cmpuint (group->alive_now, ==, 1);
      g_assert_cmpuint (group->alive_peak, ==, 1);
      g_assert_cmpuint (group->total_peak, ==, 1);
    }
    else
      g_assert_not_reached ();
  }

  gum_allocation_group_list_free (groups);
}

ALLOCTRACKER_TESTCASE (filter_function)
{
  GumAllocationTracker * t = fixture->tracker;
  guint counter = 0;

  gum_allocation_tracker_set_filter_function (t, filter_cb, &counter);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (counter, ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 42);
  g_assert_cmpuint (counter, ==, 2);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_B, DUMMY_BLOCK_C, 84);
  g_assert_cmpuint (counter, ==, 3);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
}

static gboolean
filter_cb (GumAllocationTracker * tracker,
           gpointer address,
           guint size,
           gpointer user_data)
{
  guint * counter = (guint *) user_data;

  (*counter)++;

  return (size == 1337);
}

ALLOCTRACKER_TESTCASE (realloc_new_block)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
}

ALLOCTRACKER_TESTCASE (realloc_unknown_block)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

ALLOCTRACKER_TESTCASE (realloc_zero_size)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, NULL, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

ALLOCTRACKER_TESTCASE (realloc_backtrace)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  GumList * blocks_before, * blocks_after;
  GumReturnAddressArray * addrs_before, * addrs_after;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);

  blocks_before = gum_allocation_tracker_peek_block_list (t);
  addrs_before = &GUM_ALLOCATION_BLOCK (blocks_before->data)->return_addresses;

  GUM_FAKE_BACKTRACER (backtracer)->ret_addrs = dummy_return_addresses_b;
  GUM_FAKE_BACKTRACER (backtracer)->num_ret_addrs =
      G_N_ELEMENTS (dummy_return_addresses_b);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 84);

  blocks_after = gum_allocation_tracker_peek_block_list (t);
  addrs_after = &GUM_ALLOCATION_BLOCK (blocks_after->data)->return_addresses;

  g_assert (gum_return_address_array_is_equal (addrs_before, addrs_after));

  gum_allocation_block_list_free (blocks_before);
  gum_allocation_block_list_free (blocks_after);

  g_object_unref (t);
  g_object_unref (backtracer);
}

ALLOCTRACKER_TESTCASE (backtracer_gtype_interop)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * tracker;
  GumAllocatorProbe * probe;
  ZooZebra * zebra;

  backtracer = gum_backtracer_make_default ();
  tracker = gum_allocation_tracker_new_with_backtracer (backtracer);
  gum_allocation_tracker_begin (tracker);

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "allocation-tracker", tracker, NULL);
  gum_allocator_probe_attach (probe);

  zebra = ZOO_ZEBRA (g_object_new (ZOO_TYPE_ZEBRA, NULL));
  g_object_unref (zebra);

  g_object_unref (probe);
  g_object_unref (tracker);
  g_object_unref (backtracer);
}

#if 0

ALLOCTRACKER_TESTCASE (avoid_heap_priv)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 321);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_B, 10);
  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_B, DUMMY_BLOCK_C, 20);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

ALLOCTRACKER_TESTCASE (avoid_heap_public)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  GumList * blocks, * groups;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 321);
  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_B, 10);
  blocks = gum_allocation_tracker_peek_block_list (t);
  gum_allocation_block_list_free (blocks);
  groups = gum_allocation_tracker_peek_block_groups (t);
  gum_allocation_group_list_free (groups);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

ALLOCTRACKER_TESTCASE (hashtable_resize)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  guint i;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  for (i = 0; i < 100; i++)
  {
    gum_allocation_tracker_on_malloc (t, GUINT_TO_POINTER (0xf00d + i), i + 1);
    g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  }
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

ALLOCTRACKER_TESTCASE (hashtable_life)
{
  GumSampler * heap_access_counter;
  GumHashTable * hashtable;
  guint i;

  heap_access_counter = heap_access_counter_new ();
  hashtable = gum_hash_table_new (NULL, NULL);
  for (i = 0; i < 10000; i++)
  {
    gum_hash_table_insert (hashtable, GUINT_TO_POINTER (i + 1),
        GUINT_TO_POINTER (2 * i));
  }
  gum_hash_table_unref (hashtable);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);

  g_object_unref (heap_access_counter);
}

#endif
