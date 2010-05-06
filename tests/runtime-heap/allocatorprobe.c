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
#if defined (G_OS_WIN32) && defined (_DEBUG)
#include <crtdbg.h>
#endif
#include <stdlib.h>
#include "dummyclasses.h"

#define READ_PROBE_COUNTERS() \
  g_object_get (probe,\
      "malloc-count", &malloc_count,\
      "realloc-count", &realloc_count,\
      "free-count", &free_count,\
      NULL);

#if defined (G_OS_WIN32) && defined (_DEBUG)
static void do_nonstandard_heap_calls (GumAllocatorProbe * probe,
    gint block_type, gint factor);
#endif

static void
test_basics (void)
{
  GumAllocatorProbe * probe;
  guint malloc_count, realloc_count, free_count;
  gpointer a, b;

  probe = gum_allocator_probe_new ();

  g_object_set (probe, "enable-counters", TRUE, NULL);

  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  a = malloc (314);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);
  free (a);

  gum_allocator_probe_attach (probe);

  a = malloc (42);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 1);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  b = calloc (1, 48);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 2);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  a = realloc (a, 84);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 2);
  g_assert_cmpuint (realloc_count, ==, 1);
  g_assert_cmpuint (free_count, ==, 0);

  free (b);
  free (a);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 2);
  g_assert_cmpuint (realloc_count, ==, 1);
  g_assert_cmpuint (free_count, ==, 2);

  gum_allocator_probe_detach (probe);

  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  g_object_unref (probe);
}

static void
test_ignore_gquark (void)
{
  GumAllocatorProbe * probe;
  guint malloc_count, realloc_count, free_count;

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "enable-counters", TRUE, NULL);
  gum_allocator_probe_attach (probe);

  g_quark_from_static_string ("gumtestquark1");
  g_quark_from_string ("gumtestquark2");

  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  gum_allocator_probe_detach (probe);
  g_object_unref (probe);
}

static void
test_nonstandard_basics (void)
{
#if defined (G_OS_WIN32) && defined (_DEBUG)
  GumAllocatorProbe * probe;

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "enable-counters", TRUE, NULL);
  gum_allocator_probe_attach (probe);

  do_nonstandard_heap_calls (probe, _NORMAL_BLOCK, 1);

  gum_allocator_probe_detach (probe);
  g_object_unref (probe);
#endif
}

static void
test_nonstandard_ignored (void)
{
#if defined (G_OS_WIN32) && defined (_DEBUG)
  GumAllocatorProbe * probe;

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "enable-counters", TRUE, NULL);
  gum_allocator_probe_attach (probe);

  do_nonstandard_heap_calls (probe, _CRT_BLOCK, 0);

  gum_allocator_probe_detach (probe);
  g_object_unref (probe);
#endif
}

static void
test_full_cycle (void)
{
  GumAllocatorProbe * p;
  GumAllocationTracker * t;
  gpointer a, b;

  p = gum_allocator_probe_new ();

  t = gum_allocation_tracker_new ();
  gum_allocation_tracker_begin (t);

  g_object_set (p, "allocation-tracker", t, NULL);

  gum_allocator_probe_attach (p);

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);

  a = malloc (24);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 24);

  b = calloc (2, 42);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 108);

  a = realloc (a, 40);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 124);

  free (a);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 84);

  free (b);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);

  g_object_unref (t);
  g_object_unref (p);
}

/*
 * Turns out that doing any GType lookups from within the context where
 * malloc() or similar is being called can be dangerous, as the caller
 * might be from within GType itself. The caller could hold a lock that
 * we try to reacquire by re-entering into GType, which is bad.
 *
 * We circumvent such issues by storing away as much as possible, which
 * also improves performance.
 *
 * FIXME: This test covers both AllocatorProbe and Interceptor, so the
 *        latter should obviously also have a test covering its own layer.
 */
static void
test_gtype_interop (void)
{
  GumAllocatorProbe * probe;
  MyPony * pony;

  probe = gum_allocator_probe_new ();
  gum_allocator_probe_attach (probe);

  pony = g_object_new (MY_TYPE_PONY, NULL);
  g_object_unref (pony);

  g_object_unref (probe);
}

#if defined (G_OS_WIN32) && defined (_DEBUG)

static void
do_nonstandard_heap_calls (GumAllocatorProbe * probe,
                           gint block_type,
                           gint factor)
{
  guint malloc_count, realloc_count, free_count;
  gpointer a, b;

  a = _malloc_dbg (42, block_type, __FILE__, __LINE__);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count,  ==, 1 * factor);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count,    ==, 0);

  b = _calloc_dbg (1, 48, block_type, __FILE__, __LINE__);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count,  ==, 2 * factor);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count,    ==, 0);

  a = _realloc_dbg (a, 84, block_type, __FILE__, __LINE__);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count,  ==, 2 * factor);
  g_assert_cmpuint (realloc_count, ==, 1 * factor);
  g_assert_cmpuint (free_count,    ==, 0);

  b = _recalloc_dbg (b, 2, 48, block_type, __FILE__, __LINE__);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count,  ==, 2 * factor);
  g_assert_cmpuint (realloc_count, ==, 2 * factor);
  g_assert_cmpuint (free_count,    ==, 0);

  _free_dbg (b, block_type);
  _free_dbg (a, block_type);
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count,  ==, 2 * factor);
  g_assert_cmpuint (realloc_count, ==, 2 * factor);
  g_assert_cmpuint (free_count,    ==, 2 * factor);
}

#endif

void
gum_test_register_allocator_probe_tests (void)
{
  g_test_add_func ("/Gum/AllocatorProbe/test-basics", &test_basics);
  g_test_add_func ("/Gum/AllocationTracker/test-ignore-gquark",
      &test_ignore_gquark);
  g_test_add_func ("/Gum/AllocatorProbe/NonStandard/test-basics",
      &test_nonstandard_basics);
  g_test_add_func ("/Gum/AllocatorProbe/NonStandard/test-ignored",
      &test_nonstandard_ignored);
  g_test_add_func ("/Gum/AllocatorProbe/test-full-cycle", &test_full_cycle);
  g_test_add_func ("/Gum/AllocatorProbe/test-gtype-interop",
      &test_gtype_interop);
}
