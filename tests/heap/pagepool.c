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

#include "gumpagepool.h"
#include "gummemory.h"

#include <string.h>

static void
test_alloc_sizes (void)
{
  GumPagePool * pool;
  guint page_size;
  gpointer p1, p2;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 4);
  g_object_get (pool, "page-size", &page_size, NULL);

  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 4);

  p1 = gum_page_pool_try_alloc (pool, 1);
  g_assert (p1 != NULL);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 2);

  p2 = gum_page_pool_try_alloc (pool, page_size + 1);
  g_assert (p2 == NULL);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 2);
  p2 = gum_page_pool_try_alloc (pool, page_size);
  g_assert (p2 != NULL);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 0);

  g_object_unref (pool);
}

static void
test_alloc_alignment (void)
{
  GumPagePool * pool;
  guint page_size;
  guint8 * start, * end;
  guint8 * p1, * p2;
  guint8 * expected_p1, * expected_p2;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 4);
  g_object_get (pool, "page-size", &page_size, NULL);
  gum_page_pool_get_bounds (pool, &start, &end);

  p1 = gum_page_pool_try_alloc (pool, 1);
  p2 = gum_page_pool_try_alloc (pool, 17);
  g_assert_cmphex (GPOINTER_TO_SIZE (p1), !=, GPOINTER_TO_SIZE (p2));

  expected_p1 = start + page_size - 16;
  g_assert_cmphex (GPOINTER_TO_SIZE (p1), ==, GPOINTER_TO_SIZE (expected_p1));

  expected_p2 = start + (2 * page_size) + page_size - 32;
  g_assert_cmphex (GPOINTER_TO_SIZE (p2), ==, GPOINTER_TO_SIZE (expected_p2));

  g_object_unref (pool);
}

static void
test_alloc_protection (void)
{
  GumPagePool * pool;
  guint8 * p1, * p2;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 4);

  p1 = gum_page_pool_try_alloc (pool, 1);
  g_assert (gum_memory_is_readable (p1, 16));
  g_assert (!gum_memory_is_readable (p1 + 16, 1));

  p2 = gum_page_pool_try_alloc (pool, 17);
  g_assert (gum_memory_is_readable (p2, 32));
  g_assert (!gum_memory_is_readable (p2 + 32, 1));

  g_object_unref (pool);
}

static void
test_free (void)
{
  GumPagePool * pool;
  guint page_size;
  guint8 * p1, * p2;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 5);
  g_object_get (pool, "page-size", &page_size, NULL);

  g_assert (!gum_page_pool_try_free (pool, GSIZE_TO_POINTER (1)));

  p1 = gum_page_pool_try_alloc (pool, page_size + 1);
  p2 = gum_page_pool_try_alloc (pool, 1);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 0);

  g_assert (gum_page_pool_try_free (pool, p1));
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 3);
  p1 = gum_page_pool_try_alloc (pool, page_size + 1);
  g_assert (p1 != NULL);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 0);

  g_assert (gum_page_pool_try_free (pool, p2));
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 2);
  p2 = gum_page_pool_try_alloc (pool, 1);
  g_assert (p2 != NULL);
  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 0);

  g_object_unref (pool);
}

static void
test_free_protection (void)
{
  GumPagePool * pool;
  guint8 * p;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 4);

  p = gum_page_pool_try_alloc (pool, 1);
  g_assert (gum_page_pool_try_free (pool, p));
  g_assert (!gum_memory_is_readable (p, 16));
  g_assert (!gum_memory_is_readable (p + 16, 1));

  g_object_unref (pool);
}

static void
test_query_block_size (void)
{
  GumPagePool * pool;
  guint8 * p;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 2);

  g_assert_cmpuint (gum_page_pool_query_block_size (pool,
      GSIZE_TO_POINTER (1)), ==, 0);
  p = gum_page_pool_try_alloc (pool, 1337);
  g_assert_cmpuint (gum_page_pool_query_block_size (pool, p), ==, 1337);

  g_object_unref (pool);
}

static void
test_peek_used (void)
{
  GumPagePool * pool;
  guint8 * p;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, 2);

  g_assert_cmpuint (gum_page_pool_peek_used (pool), ==, 0);
  p = gum_page_pool_try_alloc (pool, 1337);
  g_assert_cmpuint (gum_page_pool_peek_used (pool), ==, 2);
  gum_page_pool_try_free (pool, p);
  g_assert_cmpuint (gum_page_pool_peek_used (pool), ==, 0);

  g_object_unref (pool);
}

static void
test_alloc_and_fill_full_cycle (void)
{
  guint page_size, pool_size;
  GumPagePool * pool;
  guint8 * start, * end;
  guint8 * p;
  guint i;
  guint buffer_size;

  page_size = gum_query_page_size ();
  buffer_size = (3 * page_size) + 1;
  pool_size = (buffer_size / page_size) + 1;
  if (buffer_size % page_size != 0)
    pool_size++;

  pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE, pool_size);
  gum_page_pool_get_bounds (pool, &start, &end);

  p = gum_page_pool_try_alloc (pool, buffer_size);
  g_assert (p != NULL);

  g_assert_cmpuint (gum_page_pool_peek_available (pool), ==, 0);

  g_assert_cmpuint (p - start, ==, 4080);
  g_assert_cmpuint ((end - (p + buffer_size)) - page_size, ==, 15);

  for (i = 0; i < pool_size - 1; i++)
  {
    g_assert (gum_memory_is_readable (start + (i * page_size), page_size));
  }
  g_assert (!gum_memory_is_readable (end - page_size, page_size));

  memset (p, 0, buffer_size);

  g_object_unref (pool);
}

void
gum_test_register_page_pool_tests (void)
{
  g_test_add_func ("/Gum/PagePool/test-alloc-sizes", &test_alloc_sizes);
  g_test_add_func ("/Gum/PagePool/test-alloc-alignment",
      &test_alloc_alignment);
  g_test_add_func ("/Gum/PagePool/test-alloc-protection",
      &test_alloc_protection);
  g_test_add_func ("/Gum/PagePool/test-free", &test_free);
  g_test_add_func ("/Gum/PagePool/test-free-protection",
      &test_free_protection);
  g_test_add_func ("/Gum/PagePool/test-query-block-size",
      &test_query_block_size);
  g_test_add_func ("/Gum/PagePool/test-peek-used", &test_peek_used);
  g_test_add_func ("/Gum/PagePool/test-alloc-and-fill-full-cycle",
      &test_alloc_and_fill_full_cycle);
}
