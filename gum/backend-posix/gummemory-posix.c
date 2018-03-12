/*
 * Copyright (C) 2008-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gumprocess-priv.h"

#include <unistd.h>
#include <sys/mman.h>

#if defined (HAVE_LINUX)
# define GUM_MAP_LAZY MAP_NORESERVE
#elif defined (HAVE_QNX)
# define GUM_MAP_LAZY MAP_LAZY
#else
# error Unsupported OS
#endif

typedef struct _GumAllocNearContext GumAllocNearContext;
typedef struct _GumEnumerateFreeRangesContext GumEnumerateFreeRangesContext;

struct _GumAllocNearContext
{
  gpointer result;
  gsize size;
  gint posix_page_prot;
  const GumAddressSpec * address_spec;
};

struct _GumEnumerateFreeRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
  GumAddress prev_end;
};

static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumRangeDetails * details, gpointer user_data);

static void gum_enumerate_free_ranges (GumFoundRangeFunc func,
    gpointer user_data);
static gboolean gum_emit_free_range (const GumRangeDetails * details,
    gpointer user_data);

void
_gum_memory_backend_init (void)
{
}

void
_gum_memory_backend_deinit (void)
{
}

guint
_gum_memory_backend_query_page_size (void)
{
  return sysconf (_SC_PAGE_SIZE);
}

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  guint8 * result;
  guint page_size, size;

  page_size = gum_query_page_size ();
  size = (1 + n_pages) * page_size;

  result = gum_memory_allocate (size, page_prot, NULL);
  g_assert (result != NULL);

  if ((page_prot & GUM_PAGE_WRITE) == 0)
    gum_mprotect (result, page_size, GUM_PAGE_RW);
  *((gsize *) result) = size;
  gum_mprotect (result, page_size, GUM_PAGE_READ);

  return result + page_size;
}

gpointer
gum_try_alloc_n_pages_near (guint n_pages,
                            GumPageProtection page_prot,
                            const GumAddressSpec * address_spec)
{
  GumAllocNearContext ctx;
  gsize page_size;

  page_size = gum_query_page_size ();

  ctx.result = NULL;
  ctx.size = (1 + n_pages) * page_size;
  ctx.posix_page_prot = _gum_page_protection_to_posix (page_prot);
  ctx.address_spec = address_spec;

  gum_enumerate_free_ranges (gum_try_alloc_in_range_if_near_enough, &ctx);
  if (ctx.result == NULL)
    return NULL;

  if ((page_prot & GUM_PAGE_WRITE) == 0)
    gum_mprotect (ctx.result, page_size, GUM_PAGE_RW);
  *((gsize *) ctx.result) = ctx.size;
  gum_mprotect (ctx.result, page_size, GUM_PAGE_READ);

  return ctx.result + page_size;
}

static gboolean
gum_try_alloc_in_range_if_near_enough (const GumRangeDetails * details,
                                       gpointer user_data)
{
  const GumMemoryRange * range = details->range;
  GumAllocNearContext * ctx = user_data;
  GumAddress base_address;
  gsize distance;

  if (range->size < ctx->size)
    return TRUE;

  base_address = range->base_address;
  distance = ABS (ctx->address_spec->near_address -
      GSIZE_TO_POINTER (base_address));
  if (distance > ctx->address_spec->max_distance)
  {
    base_address = range->base_address + range->size - ctx->size;
    distance = ABS (ctx->address_spec->near_address -
        GSIZE_TO_POINTER (base_address));
  }

  if (distance > ctx->address_spec->max_distance)
    return TRUE;

  ctx->result = mmap (GSIZE_TO_POINTER (base_address), ctx->size,
      ctx->posix_page_prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (ctx->result == MAP_FAILED)
    ctx->result = NULL;
  else
    return FALSE;

  return TRUE;
}

void
gum_query_page_allocation_range (gconstpointer mem,
                                 guint size,
                                 GumMemoryRange * range)
{
  gsize page_size = gum_query_page_size ();

  range->base_address = GUM_ADDRESS (mem - page_size);
  range->size = size + page_size;
}

void
gum_free_pages (gpointer mem)
{
  guint8 * start;
  gsize size;
  gboolean success;

  start = mem - gum_query_page_size ();
  size = *((gsize *) start);

  success = gum_memory_release (start, size);
  g_assert (success);
}

gpointer
gum_memory_allocate (gsize size,
                     GumPageProtection page_prot,
                     gpointer hint)
{
  gpointer result;
  gint posix_page_prot, flags;

  posix_page_prot = _gum_page_protection_to_posix (page_prot);
  flags = MAP_PRIVATE | MAP_ANONYMOUS;

  result = mmap (hint, size, posix_page_prot, flags, -1, 0);

  return (result != MAP_FAILED) ? result : NULL;
}

gpointer
gum_memory_reserve (gsize size,
                    gpointer hint)
{
  gpointer result;
  gint posix_page_prot, flags;

  posix_page_prot = PROT_NONE;
  flags = MAP_PRIVATE | MAP_ANONYMOUS | GUM_MAP_LAZY;

  result = mmap (hint, size, posix_page_prot, flags, -1, 0);

  return (result != MAP_FAILED) ? result : NULL;
}

gboolean
gum_memory_commit (gpointer base,
                   gsize size,
                   GumPageProtection page_prot)
{
  gint posix_page_prot, flags;

  posix_page_prot = _gum_page_protection_to_posix (page_prot);
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;

  return mmap (base, size, posix_page_prot, flags, -1, 0) != MAP_FAILED;
}

gboolean
gum_memory_uncommit (gpointer base,
                     gsize size)
{
  gint posix_page_prot, flags;

  posix_page_prot = PROT_NONE;
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | GUM_MAP_LAZY;

  return mmap (base, size, posix_page_prot, flags, -1, 0) != MAP_FAILED;
}

gboolean
gum_memory_release_partial (gpointer base,
                            gsize size,
                            gpointer free_start,
                            gsize free_size)
{
  return munmap (free_start, free_size) == 0;
}

gboolean
gum_memory_release (gpointer base,
                    gsize size)
{
  return munmap (base, size) == 0;
}

static void
gum_enumerate_free_ranges (GumFoundRangeFunc func,
                           gpointer user_data)
{
  GumEnumerateFreeRangesContext ctx = { func, user_data, 0 };

  _gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS, gum_emit_free_range, &ctx);
}

static gboolean
gum_emit_free_range (const GumRangeDetails * details,
                     gpointer user_data)
{
  GumEnumerateFreeRangesContext * ctx =
      (GumEnumerateFreeRangesContext *) user_data;
  const GumMemoryRange * range = details->range;
  GumAddress start = range->base_address;
  GumAddress end = start + range->size;
  gboolean carry_on = TRUE;

  if (ctx->prev_end != 0)
  {
    GumAddress gap_size;

    gap_size = start - ctx->prev_end;

    if (gap_size > 0)
    {
      GumRangeDetails d;
      GumMemoryRange r;

      d.range = &r;
      d.prot = GUM_PAGE_NO_ACCESS;
      d.file = NULL;

      r.base_address = ctx->prev_end;
      r.size = gap_size;

      carry_on = ctx->func (&d, ctx->user_data);
    }
  }

  ctx->prev_end = end;

  return carry_on;
}

gint
_gum_page_protection_to_posix (GumPageProtection page_prot)
{
  gint posix_page_prot = PROT_NONE;

  if ((page_prot & GUM_PAGE_READ) != 0)
    posix_page_prot |= PROT_READ;
  if ((page_prot & GUM_PAGE_WRITE) != 0)
    posix_page_prot |= PROT_WRITE;
  if ((page_prot & GUM_PAGE_EXECUTE) != 0)
    posix_page_prot |= PROT_EXEC;

  return posix_page_prot;
}

