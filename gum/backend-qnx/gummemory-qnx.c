/*
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumqnx-priv.h"

#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>

static gboolean gum_memory_get_protection (GumAddress address, gsize n,
    gsize * size, GumPageProtection * prot);

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  msync (address, size, MS_SYNC | MS_INVALIDATE_ICACHE);
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
  int fd = -1;
  guint8 * buffer = NULL;
  gint num_read = 0;
  gint res = 0;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);
  res = lseek (fd, address, SEEK_SET);
  g_assert (res == address);

  buffer = g_malloc (len);
  num_read = read (fd, buffer, len);
  if (num_read == -1)
  {
    g_free (buffer);
    buffer = NULL;
  }
  if (n_bytes_read != NULL)
    *n_bytes_read = num_read;

  close (fd);

  return buffer;
}

gboolean
gum_memory_write (GumAddress address,
                  guint8 * bytes,
                  gsize len)
{
  gboolean success = FALSE;
  int fd = -1;
  gint res = 0;
  gint num_written = 0;

  if (!gum_memory_is_writable (address, len))
    return success;

  fd = open ("/proc/self/as", O_RDWR);
  g_assert (fd != -1);
  res = lseek (fd, address, SEEK_SET);
  g_assert (res == address);

  num_written = write (fd, bytes, len);
  if (num_written == len)
    success = TRUE;

  close (fd);

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
  if (result == -1 && errno == EACCES &&
      (page_prot & GUM_PAGE_WRITE) == GUM_PAGE_WRITE)
  {
    int fd = -1;
    char * buffer;
    gpointer address_mmaped;
    gint read_count;

    fd = open ("/proc/self/as", O_RDONLY);
    g_assert (fd != -1);

    buffer = g_alloca (aligned_size);
    g_assert (buffer != NULL);

    lseek (fd, GPOINTER_TO_SIZE (aligned_address), SEEK_SET);

    read_count = read (fd, buffer, aligned_size);
    if (read_count != aligned_size)
    {
      close (fd);

      return FALSE;
    }

    address_mmaped = mmap (aligned_address, aligned_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, NOFD, 0);
    g_assert (address_mmaped == aligned_address);

    memcpy (aligned_address, buffer, aligned_size);

    result = mprotect (aligned_address, aligned_size, posix_page_prot);

    close (fd);
  }

  return result == 0;
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
  gint i;

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

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      sizeof (procfs_mapinfo) * num_mapinfos, &num_mapinfos);
  g_assert (res == 0);

  for (i = 0; i != num_mapinfos; i++)
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
  }

  g_free (mapinfos);
  close (fd);

  return success;
}

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
