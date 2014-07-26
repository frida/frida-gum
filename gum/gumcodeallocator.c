/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodeallocator.h"

#include "gummemory.h"

#if defined (HAVE_I386) || defined (HAVE_ARM)
# define GUM_CODE_ALLOCATOR_MAX_DISTANCE (G_MAXINT32 - 16384)
#elif defined (HAVE_ARM64)
# define GUM_CODE_ALLOCATOR_MAX_DISTANCE (G_MAXINT64 - 16384)
#endif

typedef struct _GumCodePage GumCodePage;

struct _GumCodePage
{
  GumCodeSlice slice[1];
};

static GumCodePage * gum_code_allocator_new_page_near (GumCodeAllocator * self,
    gpointer address);
static void gum_code_page_free (GumCodePage * self);
static gboolean gum_code_page_is_near (GumCodePage * self, gpointer address);

static gboolean gum_code_slice_is_free (GumCodeSlice * slice);
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
  gum_list_foreach (allocator->pages, (GFunc) gum_code_page_free, NULL);
  gum_list_free (allocator->pages);
  allocator->pages = NULL;
}

GumCodeSlice *
gum_code_allocator_new_slice_near (GumCodeAllocator * self,
                                   gpointer address)
{
  GumList * walk;
  GumCodePage * cp;
  GumCodeSlice * slice;

  for (walk = self->pages; walk != NULL; walk = walk->next)
  {
    GumCodePage * page = (GumCodePage *) walk->data;

    if (gum_code_page_is_near (page, address))
    {
      guint slice_idx;

      for (slice_idx = 0; slice_idx != self->slices_per_page; slice_idx++)
      {
        slice = &page->slice[slice_idx];

        if (gum_code_slice_is_free (slice))
        {
          if (!gum_query_is_rwx_supported ())
            gum_mprotect (page, self->page_size, GUM_PAGE_RW);
          gum_code_slice_mark_taken (slice);
          return slice;
        }
      }
    }
  }

  cp = gum_code_allocator_new_page_near (self, address);
  self->pages = gum_list_prepend (self->pages, cp);

  slice = &cp->slice[0];
  gum_code_slice_mark_taken (slice);
  return slice;
}

void
gum_code_allocator_free_slice (GumCodeAllocator * self,
                               GumCodeSlice * slice)
{
  GumCodePage * cp;
  guint slice_idx;
  gboolean is_empty;

  cp = (GumCodePage *) (GPOINTER_TO_SIZE (slice) & ~(self->page_size - 1));

  if (!gum_query_is_rwx_supported ())
    gum_mprotect (cp, self->page_size, GUM_PAGE_RW);

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
    gum_code_page_free (cp);
  }
  else if (!gum_query_is_rwx_supported ())
  {
    gum_mprotect (cp, self->page_size, GUM_PAGE_RX);
  }
}

static GumCodePage *
gum_code_allocator_new_page_near (GumCodeAllocator * self,
                                  gpointer address)
{
  GumPageProtection prot;
  GumAddressSpec spec;
  GumCodePage * cp;
  guint slice_idx;

  prot = gum_query_is_rwx_supported () ? GUM_PAGE_RWX : GUM_PAGE_RW;

  spec.near_address = address;
  spec.max_distance = GUM_CODE_ALLOCATOR_MAX_DISTANCE;

  cp = (GumCodePage *) gum_alloc_n_pages_near (1, prot, &spec);

  for (slice_idx = 0; slice_idx != self->slices_per_page; slice_idx++)
  {
    GumCodeSlice * slice = &cp->slice[slice_idx];

    slice->data =
        (guint8 *) cp + self->header_size + (slice_idx * self->slice_size);
    slice->size = self->slice_size;
    gum_code_slice_mark_free (slice);
  }

  return cp;
}

static void
gum_code_page_free (GumCodePage * self)
{
  gum_free_pages (self);
}

static gboolean
gum_code_page_is_near (GumCodePage * self,
                       gpointer address)
{
  gssize distance;

  distance = ABS ((gssize) address - (gssize) self);

  return distance <= GUM_CODE_ALLOCATOR_MAX_DISTANCE;
}

static gboolean
gum_code_slice_is_free (GumCodeSlice * slice)
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
