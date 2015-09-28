/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodeallocator.h"

#include "gummemory.h"

#define GUM_CODE_PAGE(ptr, allocator) \
    ((GumCodePage *) (GPOINTER_TO_SIZE (GUM_CODE_PAGE_DATA (ptr, allocator)) + \
    allocator->page_size - allocator->header_size))
#define GUM_CODE_PAGE_DATA(ptr, allocator) \
    (GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~(allocator->page_size - 1)))

typedef struct _GumCodePage GumCodePage;

struct _GumCodePage
{
  GumCodeSlice slice[1];
};

static GumCodePage * gum_code_allocator_try_alloc_page_near (
    GumCodeAllocator * self, const GumAddressSpec * spec);
static void gum_code_page_free (GumCodePage * self,
    const GumCodeAllocator * allocator);
static gboolean gum_code_allocator_page_is_near (const GumCodeAllocator * self,
    const GumCodePage * page, const GumAddressSpec * spec);

static gboolean gum_code_slice_is_aligned (const GumCodeSlice * slice,
    gsize alignment);
static gboolean gum_code_slice_is_free (const GumCodeSlice * slice);
static void gum_code_slice_mark_free (GumCodeSlice * slice);
static void gum_code_slice_mark_taken (GumCodeSlice * slice);

void
gum_code_allocator_init (GumCodeAllocator * allocator,
                         guint slice_size)
{
  allocator->pages = NULL;
  allocator->page_size = gum_query_page_size ();

  allocator->slice_size = slice_size;

  if (gum_query_is_rwx_supported ())
  {
    allocator->header_size = 0;
    do
    {
      allocator->header_size += 16;
      allocator->slices_per_page =
          (allocator->page_size - allocator->header_size)
          / allocator->slice_size;
    }
    while (allocator->header_size <
        allocator->slices_per_page * sizeof (GumCodeSlice));
  }
  else
  {
    /*
     * We choose to waste some memory instead of risking stepping on existing
     * slices whenever a new one is to be initialized.
     */
    allocator->header_size = 16;
    allocator->slices_per_page = 1;
  }
}

void
gum_code_allocator_free (GumCodeAllocator * allocator)
{
  gum_list_foreach (allocator->pages, (GFunc) gum_code_page_free, allocator);
  gum_list_free (allocator->pages);
  allocator->pages = NULL;
}

GumCodeSlice *
gum_code_allocator_alloc_slice (GumCodeAllocator * self)
{
  return gum_code_allocator_try_alloc_slice_near (self, NULL, 0);
}

GumCodeSlice *
gum_code_allocator_try_alloc_slice_near (GumCodeAllocator * self,
                                         const GumAddressSpec * spec,
                                         gsize alignment)
{
  GumList * walk;
  GumCodePage * cp;
  GumCodeSlice * slice;

  for (walk = self->pages; walk != NULL; walk = walk->next)
  {
    GumCodePage * page = (GumCodePage *) walk->data;

    if (spec == NULL || gum_code_allocator_page_is_near (self, page, spec))
    {
      guint slice_idx;

      for (slice_idx = 0; slice_idx != self->slices_per_page; slice_idx++)
      {
        slice = &page->slice[slice_idx];

        if (gum_code_slice_is_free (slice) &&
            gum_code_slice_is_aligned (slice, alignment))
        {
          if (!gum_query_is_rwx_supported ())
            gum_mprotect (page, self->page_size, GUM_PAGE_RW);
          gum_code_slice_mark_taken (slice);
          return slice;
        }
      }
    }
  }

  cp = gum_code_allocator_try_alloc_page_near (self, spec);
  if (cp == NULL)
    return NULL;
  self->pages = gum_list_prepend (self->pages, cp);

  slice = &cp->slice[0];
  g_assert (gum_code_slice_is_aligned (slice, alignment));
  gum_code_slice_mark_taken (slice);
  return slice;
}

void
gum_code_allocator_free_slice (GumCodeAllocator * self,
                               GumCodeSlice * slice)
{
  GumCodePage * cp;
  gpointer data;
  guint slice_idx;
  gboolean is_empty;

  cp = GUM_CODE_PAGE (slice, self);
  data = GUM_CODE_PAGE_DATA (slice, self);

  if (!gum_query_is_rwx_supported ())
    gum_mprotect (data, self->page_size, GUM_PAGE_RW);

  gum_code_slice_mark_free (slice);

  is_empty = TRUE;
  for (slice_idx = 0; slice_idx != self->slices_per_page; slice_idx++)
  {
    if (!gum_code_slice_is_free (&cp->slice[slice_idx]))
    {
      is_empty = FALSE;
      break;
    }
  }

  if (is_empty)
  {
    self->pages = gum_list_remove (self->pages, cp);
    gum_code_page_free (cp, self);
  }
  else if (!gum_query_is_rwx_supported ())
  {
    gum_mprotect (data, self->page_size, GUM_PAGE_RX);
  }
}

static GumCodePage *
gum_code_allocator_try_alloc_page_near (GumCodeAllocator * self,
                                        const GumAddressSpec * spec)
{
  GumPageProtection prot;
  gpointer data;
  GumCodePage * cp;
  guint slice_idx;

  prot = gum_query_is_rwx_supported () ? GUM_PAGE_RWX : GUM_PAGE_RW;

  if (spec != NULL)
  {
    data = gum_try_alloc_n_pages_near (1, prot, spec);
    if (data == NULL)
      return NULL;
  }
  else
  {
    data = gum_alloc_n_pages (1, prot);
  }

  cp = GUM_CODE_PAGE (data, self);

  for (slice_idx = 0; slice_idx != self->slices_per_page; slice_idx++)
  {
    GumCodeSlice * slice = &cp->slice[slice_idx];

    slice->data = (guint8 *) data + (slice_idx * self->slice_size);
    slice->size = self->slice_size;
    gum_code_slice_mark_free (slice);
  }

  return cp;
}

static void
gum_code_page_free (GumCodePage * self,
                    const GumCodeAllocator * allocator)
{
  gum_free_pages (GUM_CODE_PAGE_DATA (self, allocator));
}

static gboolean
gum_code_allocator_page_is_near (const GumCodeAllocator * self,
                                 const GumCodePage * page,
                                 const GumAddressSpec * spec)
{
  gssize page_data, distance_start, distance_end;

  page_data = GPOINTER_TO_SIZE (GUM_CODE_PAGE_DATA (page, self));
  distance_start = ABS ((gssize) spec->near_address - page_data);
  distance_end = ABS ((gssize) spec->near_address -
      (page_data + (gssize) self->page_size));

  return distance_start <= spec->max_distance &&
      distance_end <= spec->max_distance;
}

static gboolean
gum_code_slice_is_aligned (const GumCodeSlice * slice,
                           gsize alignment)
{
  if (alignment == 0)
    return TRUE;

  return GPOINTER_TO_SIZE (slice->data) % alignment == 0;
}

static gboolean
gum_code_slice_is_free (const GumCodeSlice * slice)
{
  return (slice->size & 1) == 1;
}

static void
gum_code_slice_mark_free (GumCodeSlice * slice)
{
  slice->size |= 1;
}

static void
gum_code_slice_mark_taken (GumCodeSlice * slice)
{
  slice->size &= ~1;
}
