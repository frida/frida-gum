/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcloak.h"

#include "gummemory.h"
#include "gumspinlock.h"

#include <stdlib.h>
#include <string.h>

typedef struct _GumCloakedRange GumCloakedRange;

struct _GumCloakedRange
{
  guint8 * start;
  guint8 * end;
};

static void gum_cloak_ensure_ranges_capacity (gsize capacity);
static gint gum_cloak_index_of_range_containing (
    const GumCloakedRange * needle);
static gint gum_cloaked_range_compare_start (gconstpointer lhs,
    gconstpointer rhs);
static gint gum_cloaked_range_compare_overlap (gconstpointer lhs,
    gconstpointer rhs);

static GumSpinlock cloak_lock;
static GumCloakedRange * cloaked_ranges = NULL;
static gsize cloaked_ranges_length = 0;
static gsize cloaked_ranges_capacity = 0;

void
_gum_cloak_init (void)
{
  gum_spinlock_init (&cloak_lock);

  cloaked_ranges = gum_alloc_n_pages (1, GUM_PAGE_RW);
  cloaked_ranges_capacity = gum_query_page_size () / sizeof (GumCloakedRange);
}

void
_gum_cloak_deinit (void)
{
  gum_free_pages (cloaked_ranges);
  cloaked_ranges = NULL;
  cloaked_ranges_length = 0;
  cloaked_ranges_capacity = 0;

  gum_spinlock_free (&cloak_lock);
}

void
gum_cloak_add_range (const GumMemoryRange * range)
{
  GumCloakedRange * r;

  gum_spinlock_acquire (&cloak_lock);

  gum_cloak_ensure_ranges_capacity (cloaked_ranges_length + 1);

  r = &cloaked_ranges[cloaked_ranges_length++];
  r->start = GSIZE_TO_POINTER (range->base_address);
  r->end = r->start + range->size - 1;

  qsort (cloaked_ranges, cloaked_ranges_length, sizeof (GumCloakedRange),
      gum_cloaked_range_compare_start);

  gum_spinlock_release (&cloak_lock);
}

void
gum_cloak_remove_range (const GumMemoryRange * range)
{
  GumCloakedRange needle;

  gum_spinlock_acquire (&cloak_lock);

  needle.start = GSIZE_TO_POINTER (range->base_address);
  needle.end = needle.start + range->size - 1;

  while (TRUE)
  {
    gint index;

    index = gum_cloak_index_of_range_containing (&needle);
    if (index == -1)
      break;

    if (index != cloaked_ranges_length - 1)
    {
      memmove (cloaked_ranges + index, cloaked_ranges + index + 1,
          (cloaked_ranges_length - index - 1) * sizeof (GumCloakedRange));
    }
    cloaked_ranges_length--;
  }

  gum_spinlock_release (&cloak_lock);
}

gboolean
gum_cloak_has_address (GumAddress address)
{
  gboolean found = FALSE;

  gum_spinlock_acquire (&cloak_lock);

  if (address >= GUM_ADDRESS (cloaked_ranges) &&
      address < GUM_ADDRESS (cloaked_ranges + cloaked_ranges_capacity))
  {
    found = TRUE;
  }
  else
  {
    GumCloakedRange needle;

    needle.start = GSIZE_TO_POINTER (address);
    needle.end = needle.start;

    found = gum_cloak_index_of_range_containing (&needle) != -1;
  }

  gum_spinlock_release (&cloak_lock);

  return found;
}

static void
gum_cloak_ensure_ranges_capacity (gsize capacity)
{
  gsize size_in_bytes, page_size, size_in_pages;
  GumCloakedRange * new_ranges;

  if (cloaked_ranges_capacity >= capacity)
    return;

  size_in_bytes = capacity * sizeof (GumCloakedRange);
  page_size = gum_query_page_size ();
  size_in_pages = size_in_bytes / page_size;
  if (size_in_bytes % page_size != 0)
    size_in_pages++;

  new_ranges = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  memcpy (new_ranges, cloaked_ranges,
      cloaked_ranges_length * sizeof (GumCloakedRange));

  gum_free_pages (cloaked_ranges);
  cloaked_ranges = new_ranges;
  cloaked_ranges_capacity =
      (size_in_pages * page_size) / sizeof (GumCloakedRange);
}

static gint
gum_cloak_index_of_range_containing (const GumCloakedRange * needle)
{
  const GumCloakedRange * match;

  match = bsearch (needle, cloaked_ranges, cloaked_ranges_length,
      sizeof (GumCloakedRange), gum_cloaked_range_compare_overlap);
  if (match == NULL)
    return -1;

  return match - cloaked_ranges;
}

static gint
gum_cloaked_range_compare_start (gconstpointer lhs,
                                 gconstpointer rhs)
{
  const GumCloakedRange * l = lhs;
  const GumCloakedRange * r = rhs;

  return l->start - r->start;
}

static gint
gum_cloaked_range_compare_overlap (gconstpointer lhs,
                                   gconstpointer rhs)
{
  const GumCloakedRange * l = lhs;
  const GumCloakedRange * r = rhs;

  if (l->start >= r->start && l->end <= r->end)
    return 0;
  if (r->start >= l->start && r->end <= l->end)
    return 0;

  return l->start - r->start;
}
