/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"
#include "gumqnx-priv.h"

#include <gio/gio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/procfs.h>

GumPageProtection
_gum_page_protection_from_posix (const gint flags)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (flags & PROT_READ)
    prot |= GUM_PAGE_READ;
  if (flags & PROT_WRITE)
    prot |= GUM_PAGE_WRITE;
  if (flags & PROT_EXEC)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

static gboolean
gum_memory_get_protection (GumAddress address,
                           gsize n,
                           gsize * size,
                           GumPageProtection * prot)
{
  gboolean success;
  gint fd, res;
  procfs_mapinfo * mapinfos;
  gint num_mapinfos;
  gpointer start, end;
  gint i = 0;

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
    GumAddress page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = address & ~(page_size - 1);
    end_page = (address + n - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (start_page, 1, NULL, prot);
    if (success)
    {
      *size = page_size - (address - start_page);
      for (cur_page = start_page + page_size;
          cur_page != end_page + page_size;
          cur_page += page_size)
      {
        GumPageProtection cur_prot;

        if (gum_memory_get_protection (cur_page, 1, NULL, &cur_prot)
            && (cur_prot != GUM_PAGE_NO_ACCESS || *prot == GUM_PAGE_NO_ACCESS))
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

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  g_assert (res == 0);

  mapinfos = g_malloc (sizeof (procfs_mapinfo) * num_mapinfos);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      sizeof (procfs_mapinfo) * num_mapinfos, &num_mapinfos);
  g_assert (res == 0);

  while (i != num_mapinfos)
  {
    start = GSIZE_TO_POINTER (mapinfos[i].vaddr & 0xffffffff);
    end = start + mapinfos[i].size;

    if (GUM_ADDRESS (start) > address)
      break;
    else if (address >= GUM_ADDRESS (start) &&
        address + n -1 < GUM_ADDRESS (end))
    {
      success = TRUE;
      *size = 1;

      *prot = _gum_page_protection_from_posix (mapinfos[i].flags);
      break;
    }

    i++;
  }

  close (fd);
  g_free (mapinfos);
}


void
gum_clear_cache (gpointer address,
                 gsize size)
{
  g_assert_not_reached ();
}

gboolean
gum_memory_is_readable (GumAddress address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_READ) != 0;
}

static gboolean
gum_memory_is_writable (GumAddress address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_WRITE) != 0;
}

guint8 *
gum_memory_read (GumAddress address,
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
    result = g_memdup (GSIZE_TO_POINTER (address), result_len);
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
  gboolean success = FALSE;

  if (gum_memory_is_writable (address, len))
  {
    memcpy (GSIZE_TO_POINTER (address), bytes, len);
    success = TRUE;
  }

  return success;
}
