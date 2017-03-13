/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcloak.h"

#include "gummetalarray.h"
#include "gumspinlock.h"

#include <stdlib.h>
#include <string.h>

typedef struct _GumCloakedRange GumCloakedRange;

struct _GumCloakedRange
{
  const guint8 * start;
  const guint8 * end;
};

static gint gum_cloak_index_of_thread (GumThreadId id);

static gint gum_thread_id_compare (gconstpointer element_a,
    gconstpointer element_b);

static GumSpinlock cloak_lock;
static GumMetalArray cloaked_threads;
static GumMetalArray cloaked_ranges;

void
_gum_cloak_init (void)
{
  gum_spinlock_init (&cloak_lock);

  gum_metal_array_init (&cloaked_threads, sizeof (GumThreadId));
  gum_metal_array_init (&cloaked_ranges, sizeof (GumCloakedRange));
}

void
_gum_cloak_deinit (void)
{
  gum_metal_array_free (&cloaked_ranges);
  gum_metal_array_free (&cloaked_threads);

  gum_spinlock_free (&cloak_lock);
}

void
gum_cloak_add_thread (GumThreadId id)
{
  GumThreadId * element, * elements;
  gint i;

  gum_spinlock_acquire (&cloak_lock);

  element = NULL;

  elements = cloaked_threads.data;
  for (i = (gint) cloaked_threads.length - 1; i >= 0; i--)
  {
    if (id >= elements[i])
    {
      element = gum_metal_array_insert_at (&cloaked_threads, i + 1);
      break;
    }
  }

  if (element == NULL)
    element = gum_metal_array_insert_at (&cloaked_threads, 0);

  *element = id;

  gum_spinlock_release (&cloak_lock);
}

void
gum_cloak_remove_thread (GumThreadId id)
{
  gint index_;

  gum_spinlock_acquire (&cloak_lock);

  index_ = gum_cloak_index_of_thread (id);
  if (index_ != -1)
    gum_metal_array_remove_at (&cloaked_threads, index_);

  gum_spinlock_release (&cloak_lock);
}

gboolean
gum_cloak_has_thread (GumThreadId id)
{
  gboolean result;

  gum_spinlock_acquire (&cloak_lock);

  result = gum_cloak_index_of_thread (id) != -1;

  gum_spinlock_release (&cloak_lock);

  return result;
}

static gint
gum_cloak_index_of_thread (GumThreadId id)
{
  GumThreadId * elements, * element;

  elements = cloaked_threads.data;

  element = bsearch (&id, elements, cloaked_threads.length,
      cloaked_threads.element_size, gum_thread_id_compare);
  if (element == NULL)
    return -1;

  return element - elements;
}

static gint
gum_thread_id_compare (gconstpointer element_a,
                       gconstpointer element_b)
{
  GumThreadId a = *((GumThreadId *) element_a);
  GumThreadId b = *((GumThreadId *) element_b);

  if (a == b)
    return 0;
  if (a < b)
    return -1;
  return 1;
}

void
gum_cloak_add_range (const GumMemoryRange * range)
{
  GumCloakedRange * r;

  gum_spinlock_acquire (&cloak_lock);

  r = gum_metal_array_append (&cloaked_ranges);
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
    guint i;

    found_match = FALSE;

    gum_spinlock_acquire (&cloak_lock);

    for (i = 0; i != cloaked_ranges.length && !found_match; i++)
    {
      GumCloakedRange * cloaked;
      gsize bottom_remainder, top_remainder;
      gboolean slot_available;

      cloaked = gum_metal_array_element_at (&cloaked_ranges, i);

      if (cloaked->start >= end || start >= cloaked->end)
        continue;

      bottom_remainder = MAX (cloaked->start, start) - cloaked->start;
      top_remainder = cloaked->end - MIN (cloaked->end, end);

      found_match = TRUE;
      slot_available = TRUE;

      if (bottom_remainder + top_remainder == 0)
      {
        gum_metal_array_remove_at (&cloaked_ranges, i);
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
      guint cloaked_index;
      GumCloakedRange threads;
      GumCloakedRange ranges;

      chunk = &g_array_index (chunks, GumMemoryRange, chunk_index);
      chunk_start = GSIZE_TO_POINTER (chunk->base_address);
      chunk_end = chunk_start + chunk->size;

      gum_metal_array_get_extents (&cloaked_threads,
          (gpointer *) &threads.start, (gpointer *) &threads.end);
      gum_metal_array_get_extents (&cloaked_ranges,
          (gpointer *) &ranges.start, (gpointer *) &ranges.end);

      /* FIXME: also consider the arrays themselves */

      for (cloaked_index = 0;
          cloaked_index != 2 + cloaked_ranges.length && !found_match;
          cloaked_index++)
      {
        const GumCloakedRange * cloaked;
        const guint8 * lower_bound, * upper_bound;
        gsize bottom_remainder, top_remainder;
        gboolean chunk_available;

        if (cloaked_index == 0)
        {
          cloaked = &threads;
        }
        else if (cloaked_index == 1)
        {
          cloaked = &ranges;
        }
        else
        {
          cloaked = gum_metal_array_element_at (&cloaked_ranges,
              cloaked_index - 2);
        }

        lower_bound = MAX (cloaked->start, chunk_start);
        upper_bound = MIN (cloaked->end, chunk_end);
        if (lower_bound >= upper_bound)
          continue;

        bottom_remainder = lower_bound - chunk_start;
        top_remainder = chunk_end - upper_bound;

        found_match = TRUE;
        dirty = TRUE;
        chunk_available = TRUE;

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
              chunk->base_address = top.base_address;
              chunk->size = top.size;
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
