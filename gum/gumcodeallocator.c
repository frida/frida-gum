/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodeallocator.h"

#include "gummemory.h"
#include "gumprocess.h"
#ifdef HAVE_ARM
# include "gumthumbwriter.h"
#endif

#if defined (HAVE_ELF_H)
# include <elf.h>
#elif defined (HAVE_SYS_ELF_H)
# include <sys/elf.h>
#endif
#include <string.h>

#define GUM_CODE_PAGE(ptr, allocator) \
    ((GumCodePage *) (GPOINTER_TO_SIZE (GUM_CODE_PAGE_DATA (ptr, allocator)) + \
    allocator->page_size - allocator->header_size))
#define GUM_CODE_PAGE_DATA(ptr, allocator) \
    (GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~(allocator->page_size - 1)))

typedef struct _GumCodePage GumCodePage;
typedef struct _GumCodeDeflectorDispatcher GumCodeDeflectorDispatcher;
typedef struct _GumProbeRangeForCodeCaveContext GumProbeRangeForCodeCaveContext;

struct _GumCodePage
{
  GumCodeSlice slice[1];
};

struct _GumCodeDeflectorDispatcher
{
  GumList * callers;

  gpointer address;
  gpointer trampoline;
  gpointer thunk;

  gpointer original_data;
  gsize original_size;
};

struct _GumProbeRangeForCodeCaveContext
{
  const GumAddressSpec * caller;

  GumMemoryRange cave;
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

static GumCodeDeflectorDispatcher * gum_code_deflector_dispatcher_new (
    const GumAddressSpec * caller);
static void gum_code_deflector_dispatcher_free (
    GumCodeDeflectorDispatcher * dispatcher);
static gpointer gum_code_deflector_dispatcher_lookup (
    GumCodeDeflectorDispatcher * self, gpointer return_address);
static void gum_code_deflector_dispatcher_ensure_rw (
    GumCodeDeflectorDispatcher * self);
static void gum_code_deflector_dispatcher_ensure_rx (
    GumCodeDeflectorDispatcher * self);
static gboolean gum_probe_range_for_code_cave (const GumRangeDetails * details,
    gpointer user_data);

static void gum_code_deflector_free (GumCodeDeflector * deflector);

void
gum_code_allocator_init (GumCodeAllocator * allocator,
                         guint slice_size)
{
  allocator->pages = NULL;
  allocator->dispatchers = NULL;
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
  gum_list_foreach (allocator->dispatchers,
      (GFunc) gum_code_deflector_dispatcher_free, NULL);
  gum_list_free (allocator->dispatchers);
  allocator->dispatchers = NULL;

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
  gssize page_data;
  gsize distance_start, distance_end;

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

GumCodeDeflector *
gum_code_allocator_alloc_deflector (GumCodeAllocator * self,
                                    const GumAddressSpec * caller,
                                    gpointer return_address,
                                    gpointer target)
{
  GumCodeDeflectorDispatcher * dispatcher = NULL;
  GumList * cur;
  GumCodeDeflector * deflector;

  for (cur = self->dispatchers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflectorDispatcher * d = cur->data;
    gsize distance;

    distance = ABS ((gssize) d->address - (gssize) caller->near_address);
    if (distance <= caller->max_distance)
    {
      dispatcher = d;
      break;
    }
  }

  if (dispatcher == NULL)
  {
    dispatcher = gum_code_deflector_dispatcher_new (caller);
    if (dispatcher == NULL)
      return NULL;
    self->dispatchers = gum_list_prepend (self->dispatchers, dispatcher);
  }

  deflector = g_slice_new (GumCodeDeflector);
  deflector->return_address = return_address;
  deflector->target = target;
  deflector->trampoline = dispatcher->trampoline;

  dispatcher->callers = gum_list_prepend (dispatcher->callers, deflector);

  return deflector;
}

void
gum_code_allocator_free_deflector (GumCodeAllocator * self,
                                   GumCodeDeflector * deflector)
{
  GumList * cur;

  if (deflector == NULL)
    return;

  for (cur = self->dispatchers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflectorDispatcher * dispatcher = cur->data;
    GumList * entry;

    entry = gum_list_find (dispatcher->callers, deflector);
    if (entry != NULL)
    {
      dispatcher->callers = gum_list_delete_link (dispatcher->callers, entry);
      if (dispatcher->callers == NULL)
      {
        gum_code_deflector_dispatcher_free (dispatcher);
        self->dispatchers = gum_list_remove (self->dispatchers, dispatcher);
      }

      return;
    }
  }

  g_assert_not_reached ();
}

static GumCodeDeflectorDispatcher *
gum_code_deflector_dispatcher_new (const GumAddressSpec * caller)
{
  GumCodeDeflectorDispatcher * dispatcher;
  GumProbeRangeForCodeCaveContext ctx;
  gsize page_size, size_in_pages, size_in_bytes;

  ctx.caller = caller;

  ctx.cave.base_address = 0;
  ctx.cave.size = 0;

  gum_process_enumerate_ranges (GUM_PAGE_RX, gum_probe_range_for_code_cave,
      &ctx);

  if (ctx.cave.base_address == 0)
    return NULL;

  page_size = gum_query_page_size ();
  size_in_pages = 1;
  size_in_bytes = size_in_pages * page_size;

  dispatcher = g_slice_new (GumCodeDeflectorDispatcher);

  dispatcher->callers = NULL;

  dispatcher->address = GSIZE_TO_POINTER (ctx.cave.base_address);
  dispatcher->trampoline = dispatcher->address;
  dispatcher->thunk = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);

  dispatcher->original_data = g_memdup (dispatcher->address, ctx.cave.size);
  dispatcher->original_size = ctx.cave.size;

  {
#ifdef HAVE_ARM
    GumThumbWriter tw;

    gum_thumb_writer_init (&tw, dispatcher->thunk);
    gum_thumb_writer_put_call_address_with_arguments (&tw,
        GUM_ADDRESS (gum_code_deflector_dispatcher_lookup), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (dispatcher),
        GUM_ARG_REGISTER, ARM_REG_LR);
    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_R0);
    gum_thumb_writer_flush (&tw);

    gum_code_deflector_dispatcher_ensure_rw (dispatcher);

    gum_thumb_writer_reset (&tw, dispatcher->address);
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_R0,
        GUM_ADDRESS (dispatcher->thunk) + 1);
    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_R0);
    gum_thumb_writer_flush (&tw);
    g_assert_cmpuint (gum_thumb_writer_offset (&tw),
        <=, dispatcher->original_size);
    gum_thumb_writer_free (&tw);

    dispatcher->trampoline = dispatcher->address + 1;
#else
    (void) gum_code_deflector_dispatcher_lookup;
#endif
  }

  gum_code_deflector_dispatcher_ensure_rx (dispatcher);
  gum_clear_cache (dispatcher->address, dispatcher->original_size);

  gum_mprotect (dispatcher->thunk, size_in_bytes, GUM_PAGE_RX);
  gum_clear_cache (dispatcher->thunk, size_in_bytes);

  return dispatcher;
}

static void
gum_code_deflector_dispatcher_free (GumCodeDeflectorDispatcher * dispatcher)
{
  gum_code_deflector_dispatcher_ensure_rw (dispatcher);
  memcpy (dispatcher->address, dispatcher->original_data,
      dispatcher->original_size);
  gum_code_deflector_dispatcher_ensure_rx (dispatcher);
  g_free (dispatcher->original_data);

  gum_free_pages (dispatcher->thunk);

  gum_list_foreach (dispatcher->callers, (GFunc) gum_code_deflector_free, NULL);
  gum_list_free (dispatcher->callers);

  g_slice_free (GumCodeDeflectorDispatcher, dispatcher);
}

static gpointer
gum_code_deflector_dispatcher_lookup (GumCodeDeflectorDispatcher * self,
                                      gpointer return_address)
{
  GumList * cur;

  for (cur = self->callers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflector * caller = cur->data;

    if (caller->return_address == return_address)
      return caller->target;
  }

  g_assert_not_reached ();
  return NULL;
}

static void
gum_code_deflector_dispatcher_ensure_rw (GumCodeDeflectorDispatcher * self)
{
  GumPageProtection prot;

  prot = gum_query_is_rwx_supported () ? GUM_PAGE_RWX : GUM_PAGE_RW;

  gum_mprotect (self->address, self->original_size, prot);
}

static void
gum_code_deflector_dispatcher_ensure_rx (GumCodeDeflectorDispatcher * self)
{
  gum_mprotect (self->address, self->original_size, GUM_PAGE_RX);
}

#ifdef HAVE_LINUX

static gboolean
gum_probe_range_for_code_cave (const GumRangeDetails * details,
                               gpointer user_data)
{
  GumProbeRangeForCodeCaveContext * ctx = user_data;
  const GumAddressSpec * caller = ctx->caller;
  GumAddress cave_address = details->range->base_address + 8;
  gsize distance;
  const guint8 empty_cave[8] = { 0, };

  distance = ABS ((gssize) cave_address - (gssize) caller->near_address);
  if (distance > caller->max_distance)
    return TRUE;

  if (memcmp (GSIZE_TO_POINTER (details->range->base_address), ELFMAG, SELFMAG)
      != 0)
    return TRUE;

  if (memcmp (GSIZE_TO_POINTER (cave_address), empty_cave, sizeof (empty_cave))
      != 0)
    return TRUE;

  ctx->cave.base_address = cave_address;
  ctx->cave.size = 8;
  return FALSE;
}

#else

static gboolean
gum_probe_range_for_code_cave (const GumRangeDetails * details,
                               gpointer user_data)
{
  (void) details;
  (void) user_data;

  return FALSE;
}

#endif

static void
gum_code_deflector_free (GumCodeDeflector * deflector)
{
  g_slice_free (GumCodeDeflector, deflector);
}
