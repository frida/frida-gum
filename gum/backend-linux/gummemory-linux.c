/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "valgrind.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static gboolean gum_memory_get_protection (gconstpointer address, gsize n,
    gsize * size, GumPageProtection * prot);

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_READ) != 0;
}

static gboolean
gum_memory_is_writable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_WRITE) != 0;
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result = NULL;
  gsize result_len = 0;
  gsize size;
  GumPageProtection prot;

  if (gum_memory_get_protection (address, len, &size, &prot)
      && (prot & GUM_PAGE_READ) != 0)
  {
    result_len = MIN (len, size);
    result = g_memdup (address, result_len);
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = result_len;

  return result;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  gboolean success = FALSE;

  if (gum_memory_is_writable (address, len))
  {
    memcpy (address, bytes, len);
    success = TRUE;
  }

  return success;
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection page_prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  gint posix_page_prot;
  gint result;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  posix_page_prot = _gum_page_protection_to_posix (page_prot);

  result = mprotect (aligned_address, aligned_size, posix_page_prot);

  return result == 0;
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
#if defined (HAVE_ARM) || defined (HAVE_ARM64) || defined (HAVE_MIPS)
  __builtin___clear_cache (address, address + size);
#endif

  VALGRIND_DISCARD_TRANSLATIONS (address, size);
}

static gboolean
gum_memory_get_protection (gconstpointer address,
                           gsize n,
                           gsize * size,
                           GumPageProtection * prot)
{
  gboolean success;
  FILE * fp;
  gchar line[1024 + 1];

  if (size == NULL || prot == NULL)
  {
    gsize ignored_size;
    GumPageProtection ignored_prot;

    return gum_memory_get_protection (address, n,
        (size != NULL) ? size : &ignored_size,
        (prot != NULL) ? prot : &ignored_prot);
  }

  if (n > 1)
  {
    gsize page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = GPOINTER_TO_SIZE (address) & ~(page_size - 1);
    end_page = (GPOINTER_TO_SIZE (address) + n - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (GSIZE_TO_POINTER (start_page), 1, NULL,
        prot);
    if (success)
    {
      *size = page_size - (GPOINTER_TO_SIZE (address) - start_page);
      for (cur_page = start_page + page_size;
          cur_page != end_page + page_size;
          cur_page += page_size)
      {
        GumPageProtection cur_prot;

        if (gum_memory_get_protection (GSIZE_TO_POINTER (cur_page), 1, NULL,
            &cur_prot) && (cur_prot != GUM_PAGE_NO_ACCESS ||
            *prot == GUM_PAGE_NO_ACCESS))
        {
          *size += page_size;
          *prot &= cur_prot;
        }
        else
        {
          break;
        }
      }
      *size = MIN (*size, n);
    }

    return success;
  }

  success = FALSE;
  *size = 0;
  *prot = GUM_PAGE_NO_ACCESS;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    gpointer start, end;
    gchar protection[16];

    sscanf (line, "%p-%p %s ", &start, &end, protection);

    if (start > address)
      break;
    else if (address >= start && address + n - 1 < end)
    {
      success = TRUE;
      *size = 1;
      if (protection[0] == 'r')
        *prot |= GUM_PAGE_READ;
      if (protection[1] == 'w')
        *prot |= GUM_PAGE_WRITE;
      if (protection[2] == 'x')
        *prot |= GUM_PAGE_EXECUTE;
      break;
    }
  }

  fclose (fp);

  return success;
}

