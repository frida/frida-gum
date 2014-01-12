/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gummemory.h"

#include "gummemory-priv.h"

#include <unistd.h>
#define __USE_GNU     1
#include <sys/mman.h>
#undef __USE_GNU
#define INSECURE      0
#define NO_MALLINFO   0
#define USE_LOCKS     1
#define USE_DL_PREFIX 1
#include "dlmalloc.c"

#define GUM_MEMRANGE_IS_NOT_MAPPED(address, size) \
    (gum_memory_get_protection (address, size, NULL) == FALSE)

typedef gboolean (* GumFoundFreeRangeFunc) (const GumMemoryRange * range,
    gpointer user_data);

typedef struct _GumAllocNearContext GumAllocNearContext;

struct _GumAllocNearContext
{
  gpointer result;
  gsize size;
  gint unix_page_prot;
  GumAddressSpec * address_spec;
};

static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumMemoryRange * range, gpointer user_data);
static gint gum_page_protection_to_unix (GumPageProtection page_prot);

void
_gum_memory_init (void)
{
}

void
_gum_memory_deinit (void)
{
}

guint
gum_query_page_size (void)
{
  return sysconf (_SC_PAGE_SIZE);
}

static void
gum_memory_enumerate_free_ranges (GumFoundFreeRangeFunc func,
                                  gpointer user_data)
{
  FILE * fp;
  gboolean carry_on = TRUE;
  gchar line[1024 + 1];
  gpointer prev_end = NULL;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  while (carry_on && fgets (line, sizeof (line), fp) != NULL)
  {
    gint n;
    gpointer start, end;

    n = sscanf (line, "%p-%p ", &start, &end);
    g_assert_cmpint (n, ==, 2);

    if (prev_end != NULL)
    {
      gsize gap_size;

      gap_size = start - prev_end;

      if (gap_size > 0)
      {
        GumMemoryRange r;

        r.base_address = GUM_ADDRESS (prev_end);
        r.size = gap_size;

        carry_on = func (&r, user_data);
      }
    }

    prev_end = end;
  }

  fclose (fp);
}

static gboolean
gum_memory_get_protection (GumAddress address,
                           gsize len,
                           GumPageProtection * prot)
{
  gboolean success = FALSE;
  FILE * fp;
  gchar line[1024 + 1];

  if (prot == NULL)
  {
    GumPageProtection ignored_prot;

    return gum_memory_get_protection (address, len, &ignored_prot);
  }

  *prot = GUM_PAGE_NO_ACCESS;

  if (len > 1)
  {
    GumAddress page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = address & ~(page_size - 1);
    end_page = (address + len - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (start_page, 1, prot);

    for (cur_page = start_page + page_size;
        cur_page != end_page + page_size;
        cur_page += page_size)
    {
      GumPageProtection cur_prot;

      if (gum_memory_get_protection (cur_page, 1, &cur_prot))
      {
        success = TRUE;
        *prot &= cur_prot;
      }
      else
      {
        *prot = GUM_PAGE_NO_ACCESS;
        break;
      }
    }

    return success;
  }

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    gint n;
    gpointer start, end;
    gchar protection[16];

    n = sscanf (line, "%p-%p %s ", &start, &end, protection);
    g_assert_cmpint (n, ==, 3);

    if (GUM_ADDRESS (start) > address)
      break;
    else if (address >= GUM_ADDRESS (start) &&
        address + len - 1 < GUM_ADDRESS (end))
    {
      success = TRUE;

      if (prot != NULL)
      {
        if (protection[0] == 'r')
          *prot |= GUM_PAGE_READ;
        if (protection[1] == 'w')
          *prot |= GUM_PAGE_WRITE;
        if (protection[2] == 'x')
          *prot |= GUM_PAGE_EXECUTE;
      }

      break;
    }
  }

  fclose (fp);

  return success;
}

gboolean
gum_memory_is_readable (GumAddress address,
                        gsize len)
{
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &prot))
    return FALSE;

  return (prot & GUM_PAGE_READ) != 0;
}

static gboolean
gum_memory_is_writable (GumAddress address,
                        gsize len)
{
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &prot))
    return FALSE;

  return (prot & GUM_PAGE_WRITE) != 0;
}

guint8 *
gum_memory_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result = NULL;
  gsize result_len = 0;

  if (gum_memory_is_readable (address, len))
  {
    result = g_memdup (GSIZE_TO_POINTER (address), len);
    result_len = len;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = result_len;

  return result;
}

gboolean
gum_memory_write (GumAddress address,
                  guint8 * bytes,
                  gsize len)
{
  gboolean result = FALSE;

  if (gum_memory_is_writable (address, len))
  {
    memcpy (GSIZE_TO_POINTER (address), bytes, len);
    result = TRUE;
  }

  return result;
}

void
gum_mprotect (gpointer address,
              gsize size,
              GumPageProtection page_prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  gint unix_page_prot;
  gint result;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  unix_page_prot = gum_page_protection_to_unix (page_prot);

  result = mprotect (aligned_address, aligned_size, unix_page_prot);
  g_assert_cmpint (result, ==, 0);
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
#ifdef HAVE_ARM
  cacheflush (GPOINTER_TO_SIZE (address), GPOINTER_TO_SIZE (address + size), 0);
#endif
}

guint
gum_peek_private_memory_usage (void)
{
  struct mallinfo info;

  info = dlmallinfo ();

  return info.uordblks;
}

gpointer
gum_malloc (gsize size)
{
  return dlmalloc (size);
}

gpointer
gum_malloc0 (gsize size)
{
  return dlcalloc (1, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  return dlrealloc (mem, size);
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = dlmalloc (byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  dlfree (mem);
}

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  guint8 * result = NULL;
  guint page_size, size;
  gint unix_page_prot;
  const gint flags = MAP_PRIVATE | MAP_ANONYMOUS;

  page_size = gum_query_page_size ();
  size = (1 + n_pages) * page_size;
  unix_page_prot = gum_page_protection_to_unix (page_prot);

  result = mmap (NULL, size, unix_page_prot, flags, -1, 0);
  g_assert (result != NULL);

  gum_mprotect (result, page_size, GUM_PAGE_RW);
  *((gsize *) result) = size;
  gum_mprotect (result, page_size, GUM_PAGE_READ);

  return result + page_size;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
{
  GumAllocNearContext ctx;
  gsize page_size;

  page_size = gum_query_page_size ();

  ctx.result = NULL;
  ctx.size = (1 + n_pages) * page_size;
  ctx.unix_page_prot = gum_page_protection_to_unix (page_prot);
  ctx.address_spec = address_spec;

  gum_memory_enumerate_free_ranges (gum_try_alloc_in_range_if_near_enough,
      &ctx);

  g_assert (ctx.result != NULL);

  gum_mprotect (ctx.result, page_size, GUM_PAGE_RW);
  *((gsize *) ctx.result) = ctx.size;
  gum_mprotect (ctx.result, page_size, GUM_PAGE_READ);

  return ctx.result + page_size;
}

static gboolean
gum_try_alloc_in_range_if_near_enough (const GumMemoryRange * range,
                                       gpointer user_data)
{
  GumAllocNearContext * ctx = user_data;
  GumAddress base_address;
  gsize distance;

  if (range->size < ctx->size)
    return TRUE;

  base_address = range->base_address;
  distance = ABS (ctx->address_spec->near_address - (gpointer) base_address);
  if (distance > ctx->address_spec->max_distance)
  {
    base_address = range->base_address + range->size - ctx->size;
    distance = ABS (ctx->address_spec->near_address - (gpointer) base_address);
  }

  if (distance > ctx->address_spec->max_distance)
    return TRUE;

  ctx->result = mmap (GSIZE_TO_POINTER (base_address), ctx->size,
      ctx->unix_page_prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (ctx->result == MAP_FAILED)
    ctx->result = NULL;
  else
    return FALSE;

  return TRUE;
}

void
gum_free_pages (gpointer mem)
{
  guint8 * start;
  gsize size;
  gint result;

  start = mem - gum_query_page_size ();
  size = *((gsize *) start);

  result = munmap (start, size);
  g_assert_cmpint (result, ==, 0);
}

static gint
gum_page_protection_to_unix (GumPageProtection page_prot)
{
  gint unix_page_prot = PROT_NONE;

  if ((page_prot & GUM_PAGE_READ) != 0)
    unix_page_prot |= PROT_READ;
  if ((page_prot & GUM_PAGE_WRITE) != 0)
    unix_page_prot |= PROT_WRITE;
  if ((page_prot & GUM_PAGE_EXECUTE) != 0)
    unix_page_prot |= PROT_EXEC;

  return unix_page_prot;
}
