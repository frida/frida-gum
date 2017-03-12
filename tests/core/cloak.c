/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#define CLOAK_TESTCASE(NAME) \
    void test_cloak_ ## NAME (void)
#define CLOAK_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Cloak", test_cloak, NAME)

TEST_LIST_BEGIN (cloak)
  CLOAK_TESTENTRY (range_clip_should_not_include_uncloaked)
  CLOAK_TESTENTRY (range_clip_should_handle_full_clip)
  CLOAK_TESTENTRY (range_clip_should_handle_bottom_clip)
  CLOAK_TESTENTRY (range_clip_should_handle_middle_clip)
  CLOAK_TESTENTRY (range_clip_should_handle_top_clip)
  CLOAK_TESTENTRY (full_range_removal_should_impact_clip)
  CLOAK_TESTENTRY (partial_range_removal_should_impact_clip)
TEST_LIST_END ()

CLOAK_TESTCASE (range_clip_should_not_include_uncloaked)
{
  gpointer page;
  GumMemoryRange range;

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);

  range.base_address = GUM_ADDRESS (page);
  range.size = gum_query_page_size ();
  g_assert (gum_cloak_clip_range (&range) == NULL);

  gum_free_pages (page);
}

CLOAK_TESTCASE (range_clip_should_handle_full_clip)
{
  gpointer page;
  GumMemoryRange range;
  GArray * clipped;

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);

  range.base_address = GUM_ADDRESS (page);
  range.size = gum_query_page_size ();
  gum_cloak_add_range (&range);

  clipped = gum_cloak_clip_range (&range);
  g_assert (clipped != NULL);
  g_assert_cmpuint (clipped->len, ==, 0);
  g_array_free (clipped, TRUE);

  gum_cloak_remove_range (&range);

  gum_free_pages (page);
}

CLOAK_TESTCASE (range_clip_should_handle_bottom_clip)
{
  gpointer pages;
  guint page_size;
  GumMemoryRange cloaked_range;
  GumMemoryRange full_range;
  GArray * clipped;
  GumMemoryRange * r;

  pages = gum_alloc_n_pages (2, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  cloaked_range.base_address = GUM_ADDRESS (pages);
  cloaked_range.size = page_size;
  gum_cloak_add_range (&cloaked_range);

  full_range.base_address = GUM_ADDRESS (pages);
  full_range.size = 2 * page_size;
  clipped = gum_cloak_clip_range (&full_range);
  g_assert (clipped != NULL);
  g_assert_cmpuint (clipped->len, ==, 1);
  r = &g_array_index (clipped, GumMemoryRange, 0);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages) + page_size);
  g_assert_cmpuint (r->size, ==, page_size);
  g_array_free (clipped, TRUE);

  gum_cloak_remove_range (&cloaked_range);

  gum_free_pages (pages);
}

CLOAK_TESTCASE (range_clip_should_handle_middle_clip)
{
  gpointer pages;
  guint page_size;
  GumMemoryRange cloaked_range;
  GumMemoryRange full_range;
  GArray * clipped;
  GumMemoryRange * r;

  pages = gum_alloc_n_pages (3, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  cloaked_range.base_address = GUM_ADDRESS (pages) + page_size;
  cloaked_range.size = page_size;
  gum_cloak_add_range (&cloaked_range);

  full_range.base_address = GUM_ADDRESS (pages);
  full_range.size = 3 * page_size;
  clipped = gum_cloak_clip_range (&full_range);
  g_assert (clipped != NULL);
  g_assert_cmpuint (clipped->len, ==, 2);
  r = &g_array_index (clipped, GumMemoryRange, 0);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages));
  g_assert_cmpuint (r->size, ==, page_size);
  r = &g_array_index (clipped, GumMemoryRange, 1);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages) + (2 * page_size));
  g_assert_cmpuint (r->size, ==, page_size);
  g_array_free (clipped, TRUE);

  gum_cloak_remove_range (&cloaked_range);

  gum_free_pages (pages);
}

CLOAK_TESTCASE (range_clip_should_handle_top_clip)
{
  gpointer pages;
  guint page_size;
  GumMemoryRange cloaked_range;
  GumMemoryRange full_range;
  GArray * clipped;
  GumMemoryRange * r;

  pages = gum_alloc_n_pages (2, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  cloaked_range.base_address = GUM_ADDRESS (pages) + page_size;
  cloaked_range.size = page_size;
  gum_cloak_add_range (&cloaked_range);

  full_range.base_address = GUM_ADDRESS (pages);
  full_range.size = 2 * page_size;
  clipped = gum_cloak_clip_range (&full_range);
  g_assert (clipped != NULL);
  g_assert_cmpuint (clipped->len, ==, 1);
  r = &g_array_index (clipped, GumMemoryRange, 0);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages));
  g_assert_cmpuint (r->size, ==, page_size);
  g_array_free (clipped, TRUE);

  gum_cloak_remove_range (&cloaked_range);

  gum_free_pages (pages);
}

CLOAK_TESTCASE (full_range_removal_should_impact_clip)
{
  gpointer page;
  GumMemoryRange range;

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);

  range.base_address = GUM_ADDRESS (page);
  range.size = gum_query_page_size ();

  gum_cloak_add_range (&range);
  gum_cloak_remove_range (&range);

  g_assert (gum_cloak_clip_range (&range) == NULL);

  gum_free_pages (page);
}

CLOAK_TESTCASE (partial_range_removal_should_impact_clip)
{
  gpointer pages;
  guint page_size;
  GumMemoryRange cloaked_range;
  GumMemoryRange full_range;
  GArray * clipped;
  GumMemoryRange * r;

  pages = gum_alloc_n_pages (3, GUM_PAGE_RW);

  page_size = gum_query_page_size ();

  cloaked_range.base_address = GUM_ADDRESS (pages);
  cloaked_range.size = 3 * page_size;
  gum_cloak_add_range (&cloaked_range);
  cloaked_range.base_address = GUM_ADDRESS (pages);
  cloaked_range.size = page_size;
  gum_cloak_remove_range (&cloaked_range);
  cloaked_range.base_address = GUM_ADDRESS (pages) + (2 * page_size);
  cloaked_range.size = page_size;
  gum_cloak_remove_range (&cloaked_range);

  full_range.base_address = GUM_ADDRESS (pages);
  full_range.size = 3 * page_size;
  clipped = gum_cloak_clip_range (&full_range);
  g_assert (clipped != NULL);
  g_assert_cmpuint (clipped->len, ==, 2);
  r = &g_array_index (clipped, GumMemoryRange, 0);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages));
  g_assert_cmpuint (r->size, ==, page_size);
  r = &g_array_index (clipped, GumMemoryRange, 1);
  g_assert_cmphex (r->base_address, ==, GUM_ADDRESS (pages) + (2 * page_size));
  g_assert_cmpuint (r->size, ==, page_size);
  g_array_free (clipped, TRUE);

  cloaked_range.base_address = GUM_ADDRESS (pages) + page_size;
  cloaked_range.size = page_size;
  gum_cloak_remove_range (&cloaked_range);

  clipped = gum_cloak_clip_range (&full_range);
  g_assert (clipped == NULL);

  gum_free_pages (pages);
}
