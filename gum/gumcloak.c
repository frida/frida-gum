/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcloak.h"

#include "gummemory.h"
#include "gumspinlock.h"

#include <string.h>

typedef struct _GumCloakedRange GumCloakedRange;

struct _GumCloakedRange
{
  const guint8 * start;
  const guint8 * end;
};

static void gum_cloak_ensure_ranges_capacity (gsize capacity);

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
  r->end = r->start + range->size;

  gum_spinlock_release (&cloak_lock);
}

void
gum_cloak_remove_range (const GumMemoryRange * range)
{
  const guint8 * start, * end;
  gboolean found_match;

  start = GSIZE_TO_POINTER (range->base_address);
  end = start + range->size;

  do
  {
    gsize i;

    found_match = FALSE;

    gum_spinlock_acquire (&cloak_lock);

    for (i = 0; i != cloaked_ranges_length && !found_match; i++)
    {
      GumCloakedRange * cloaked = &cloaked_ranges[i];
      gsize bottom_remainder, top_remainder;
      gboolean slot_available;

      if (cloaked->start >= end || start >= cloaked->end)
        continue;

      bottom_remainder = MAX (cloaked->start, start) - cloaked->start;
      top_remainder = cloaked->end - MIN (cloaked->end, end);

      found_match = TRUE;
      slot_available = TRUE;

      if (bottom_remainder + top_remainder == 0)
      {
        if (i != cloaked_ranges_length - 1)
        {
          memmove (cloaked_ranges + i, cloaked_ranges + i + 1,
              (cloaked_ranges_length - i - 1) * sizeof (GumCloakedRange));
        }
        cloaked_ranges_length--;
      }
      else
      {
        if (bottom_remainder != 0)
        {
          cloaked->end = cloaked->start + bottom_remainder;
          slot_available = FALSE;
        }

        if (top_remainder != 0)
        {
          GumMemoryRange top;

          top.base_address = GUM_ADDRESS (cloaked->end - top_remainder);
          top.size = top_remainder;

          if (slot_available)
          {
            cloaked->start = GSIZE_TO_POINTER (top.base_address);
            cloaked->end = cloaked->start + top.size;
          }
          else
          {
            gum_spinlock_release (&cloak_lock);
            gum_cloak_add_range (&top);
            gum_spinlock_acquire (&cloak_lock);
          }
        }
      }
    }

    gum_spinlock_release (&cloak_lock);
  }
  while (found_match);
}

GArray *
gum_cloak_clip_range (const GumMemoryRange * range)
{
  GArray * chunks;
  gboolean found_match, dirty;

  chunks = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 2);
  g_array_append_val (chunks, *range);

  dirty = FALSE;

  do
  {
    guint chunk_index;

    found_match = FALSE;

    gum_spinlock_acquire (&cloak_lock);

    for (chunk_index = 0;
        chunk_index != chunks->len && !found_match;
        chunk_index++)
    {
      GumMemoryRange * chunk;
      const guint8 * chunk_start, * chunk_end;
      gboolean chunk_available;
      gsize cloaked_index;

      chunk = &g_array_index (chunks, GumMemoryRange, chunk_index);
      chunk_start = GSIZE_TO_POINTER (chunk->base_address);
      chunk_end = chunk_start + chunk->size;

      chunk_available = TRUE;

      for (cloaked_index = 0;
          cloaked_index != cloaked_ranges_length && !found_match;
          cloaked_index++)
      {
        const GumCloakedRange * cloaked = &cloaked_ranges[cloaked_index];
        const guint8 * lower_bound, * upper_bound;
        gsize bottom_remainder, top_remainder;

        lower_bound = MAX (cloaked->start, chunk_start);
        upper_bound = MIN (cloaked->end, chunk_end);
        if (lower_bound >= upper_bound)
          continue;

        bottom_remainder = lower_bound - chunk_start;
        top_remainder = chunk_end - upper_bound;

        found_match = TRUE;
        dirty = TRUE;

        if (bottom_remainder + top_remainder == 0)
        {
          g_array_remove_index (chunks, chunk_index);
        }
        else
        {
          if (bottom_remainder != 0)
          {
            chunk->base_address = GUM_ADDRESS (chunk_start);
            chunk->size = bottom_remainder;
            chunk_available = FALSE;
          }

          if (top_remainder != 0)
          {
            GumMemoryRange top;

            top.base_address = GUM_ADDRESS (chunk_end - top_remainder);
            top.size = top_remainder;

            if (chunk_available)
            {
              memcpy (chunk, &top, sizeof (GumMemoryRange));
            }
            else
            {
              gum_spinlock_release (&cloak_lock);
              g_array_insert_val (chunks, chunk_index + 1, top);
              gum_spinlock_acquire (&cloak_lock);
            }
          }
        }
      }
    }

    gum_spinlock_release (&cloak_lock);
  }
  while (found_match);

  if (!dirty)
  {
    g_array_free (chunks, TRUE);
    return NULL;
  }

  return chunks;
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
