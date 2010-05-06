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

#include "fakebacktracer.h"
#include "testutil.h"
#include "dummyclasses.h"
#include "../gum/gumhash.h"
#include <gum/gum.h>

#define DUMMY_BLOCK_A (GUINT_TO_POINTER (0xDEADBEEF))
#define DUMMY_BLOCK_B (GUINT_TO_POINTER (0xB00BFACE))
#define DUMMY_BLOCK_C (GUINT_TO_POINTER (0xBEEFFACE))
#define DUMMY_BLOCK_D (GUINT_TO_POINTER (0xBEEFB00B))
#define DUMMY_BLOCK_E (GUINT_TO_POINTER (0xBEB00BEF))

static const GumReturnAddress dummy_return_addresses_a[] =
{
  { GUINT_TO_POINTER (0x1234), "libpony.so", "my_pony_new", "mypony.c", 236 },
  { GUINT_TO_POINTER (0x4321), "libstable.so", "my_stable_populate",
    "mystable.c", 555 }
};

static const GumReturnAddress dummy_return_addresses_b[] =
{
  { GUINT_TO_POINTER (0x1250), "libpony.so", "my_pony_new", "mypony.c", 236 },
  { GUINT_TO_POINTER (0x4321), "libstable.so", "my_stable_populate",
    "mystable.c", 555 }
};

static gboolean filter_cb (GumAllocationTracker * tracker, gpointer address,
    guint size, gpointer user_data);
static GumBacktracer * make_backtracer (void);

static void
test_begin (void)
{
  GumAllocationTracker * t;
  GumList * blocks, * groups;

  t = gum_allocation_tracker_new ();

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

  g_object_unref (t);
}

static void
test_end (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();

  gum_allocation_tracker_begin (t);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 321);
  gum_allocation_tracker_end (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 313);

  g_assert (gum_allocation_tracker_peek_block_list (t) == NULL);
  g_assert (gum_allocation_tracker_peek_block_groups (t) == NULL);

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);

  g_object_unref (t);
}

static void
test_block_count (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();
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

  g_object_unref (t);
}

static void
test_block_total_size (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();
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

  g_object_unref (t);
}

static void
test_block_list_pointers (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();
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

  g_object_unref (t);
}

static void
test_block_list_sizes (void)
{
  GumAllocationTracker * t;
  GumList * blocks, * cur;

  t = gum_allocation_tracker_new ();
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

  g_object_unref (t);
}

static void
test_block_list_backtraces (void)
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

  block = blocks->data;
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

static void
test_block_groups (void)
{
  GumAllocationTracker * t;
  GumList * groups, * cur;

  t = gum_allocation_tracker_new ();
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
    GumAllocationGroup * group = cur->data;

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

  g_object_unref (t);
}

static void
test_filter_function (void)
{
  GumAllocationTracker * t;
  guint counter = 0;

  t = gum_allocation_tracker_new ();

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

  g_object_unref (t);
}

static gboolean
filter_cb (GumAllocationTracker * tracker,
           gpointer address,
           guint size,
           gpointer user_data)
{
  guint * counter = user_data;

  (*counter)++;

  return (size == 1337);
}

static void
test_realloc_new_block (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  g_object_unref (t);
}

static void
test_realloc_unknown_block (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);

  g_object_unref (t);
}

static void
test_realloc_zero_size (void)
{
  GumAllocationTracker * t;

  t = gum_allocation_tracker_new ();

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, NULL, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);

  g_object_unref (t);
}

static void
test_realloc_backtrace (void)
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

static void
test_backtracer_gtype_interop (void)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * tracker;
  GumAllocatorProbe * probe;
  ZooZebra * zebra;

  backtracer = make_backtracer ();
  tracker = gum_allocation_tracker_new_with_backtracer (backtracer);
  gum_allocation_tracker_begin (tracker);

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "allocation-tracker", tracker, NULL);
  gum_allocator_probe_attach (probe);

  zebra = g_object_new (ZOO_TYPE_ZEBRA, NULL);
  g_object_unref (zebra);

  g_object_unref (probe);
  g_object_unref (tracker);
  g_object_unref (backtracer);
}

static void
test_avoid_heap_priv (void)
{
  GumAllocationTracker * t;
  GumSampler * heap_access_counter;

  t = gum_allocation_tracker_new ();
  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 321);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_B, 10);
  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_B, DUMMY_BLOCK_C, 20);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
  g_object_unref (t);
}

static void
test_avoid_heap_public (void)
{
  GumAllocationTracker * t;
  GumSampler * heap_access_counter;
  GumList * blocks, * groups;

  t = gum_allocation_tracker_new ();
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
  g_object_unref (t);
}

static void
test_hashtable_resize (void)
{
  GumAllocationTracker * t;
  GumSampler * heap_access_counter;
  guint i;

  t = gum_allocation_tracker_new ();
  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  for (i = 0; i < 100; i++)
  {
    gum_allocation_tracker_on_malloc (t, GUINT_TO_POINTER (0xf00d + i), i + 1);
    g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  }
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
  g_object_unref (t);
}

static void
test_hashtable_life (void)
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

static GumBacktracer *
make_backtracer (void)
{
#ifdef G_OS_WIN32
  return gum_windows_backtracer_new ();
#else
  return gum_gnu_backtracer_new ();
#endif
}

void
gum_test_register_allocation_tracker_tests (void)
{
  g_test_add_func ("/Gum/AllocationTracker/test-begin", &test_begin);
  g_test_add_func ("/Gum/AllocationTracker/test-end", &test_end);
  g_test_add_func ("/Gum/AllocationTracker/test-block-count",
      &test_block_count);
  g_test_add_func ("/Gum/AllocationTracker/test-block-total-size",
      &test_block_total_size);
  g_test_add_func ("/Gum/AllocationTracker/test-block-list-pointers",
      &test_block_list_pointers);
  g_test_add_func ("/Gum/AllocationTracker/test-block-list-sizes",
      &test_block_list_sizes);
  g_test_add_func ("/Gum/AllocationTracker/test-block-list-backtraces",
      &test_block_list_backtraces);
  g_test_add_func ("/Gum/AllocationTracker/test-block-groups",
      &test_block_groups);
  g_test_add_func ("/Gum/AllocationTracker/test-filter-function",
      &test_filter_function);
  g_test_add_func ("/Gum/AllocationTracker/test-realloc-new-block",
      &test_realloc_new_block);
  g_test_add_func ("/Gum/AllocationTracker/test-realloc-unknown-block",
      &test_realloc_unknown_block);
  g_test_add_func ("/Gum/AllocationTracker/test-realloc-zero-size",
      &test_realloc_zero_size);
  g_test_add_func ("/Gum/AllocationTracker/test-realloc-backtrace",
      &test_realloc_backtrace);
  g_test_add_func ("/Gum/AllocationTracker/test-backtracer-gtype-interop",
      &test_backtracer_gtype_interop);
  g_test_add_func ("/Gum/AllocationTracker/PrivateHeap/test-hashtable-resize",
      &test_hashtable_resize);
  g_test_add_func ("/Gum/AllocationTracker/PrivateHeap/test-avoid-heap-priv",
      &test_avoid_heap_priv);
  g_test_add_func ("/Gum/AllocationTracker/PrivateHeap/test-avoid-heap-public",
      &test_avoid_heap_public);
  g_test_add_func ("/Gum/AllocationTracker/PrivateHeap/test-hashtable-life",
      &test_hashtable_life);
}
