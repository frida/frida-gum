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

#include "gummemory.h"

#include "gummemory-priv.h"

#include <unistd.h>
#define __USE_GNU     1
#include <sys/mman.h>
#undef __USE_GNU
#define INSECURE      0
#define NO_MALLINFO   1
#define USE_LOCKS     1
#define USE_DL_PREFIX 1
#include "dlmalloc.c"

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

gboolean
gum_memory_is_readable (gpointer address,
                        guint len)
{
  gboolean result = FALSE;
  FILE * fp;
  gchar line[1024 + 1];

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    gint n;
    gpointer start, end;
    gchar protection[16];

    n = sscanf (line, "%p-%p %s ", &start, &end, protection);
    g_assert (n == 3);

    if (start > address)
      break;
    else if (address >= start && address + len <= end)
    {
      if (protection[0] == 'r')
        result = TRUE;
      break;
    }
  }

  fclose (fp);
  return result;
}

guint8 *
gum_memory_read (gpointer address,
                 guint len,
                 gint * n_bytes_read)
{
  return NULL;
}

gboolean
gum_memory_write (gpointer address,
                  guint8 * bytes,
                  guint len)
{
  return FALSE;
}

void
gum_mprotect (gpointer address,
              guint size,
              GumPageProtection page_prot)
{
  gpointer aligned_address;
  guint unix_page_prot;
  gint result;

  g_assert (size != 0);

  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(gum_query_page_size () - 1));
  unix_page_prot = gum_page_protection_to_unix (page_prot);

  result = mprotect (aligned_address, size, unix_page_prot);
  g_assert_cmpint (result, ==, 0);
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
  guint page_size, size, alloc_size;
  gint ret;

  /* sbrk() or mmap() would probably be better choices here */
  page_size = gum_query_page_size ();
  size = n_pages * page_size;
  alloc_size = page_size + size;
  ret = posix_memalign ((void **) &result, page_size, alloc_size);
  g_assert (ret == 0);

  *((guint *) result) = size;

  result += page_size;
  memset (result, 0, size);
  gum_mprotect (result, size, page_prot);

  return result;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
{
  /* FIXME */
  return gum_alloc_n_pages (n_pages, page_prot);
}

void
gum_free_pages (gpointer mem)
{
  guint8 * start;
  guint page_size, size;

  page_size = gum_query_page_size ();
  start = (guint8 *) mem - page_size;
  size = *((guint *) start);

  gum_mprotect (mem, size, GUM_PAGE_READ | GUM_PAGE_WRITE);
  free (start);
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
