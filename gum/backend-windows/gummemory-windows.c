/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gumwindows.h"

#include <stdlib.h>

static gpointer gum_virtual_alloc (gpointer address, gsize size,
    DWORD allocation_type, DWORD page_protection);
static gboolean gum_memory_get_protection (gconstpointer address, gsize len,
    GumPageProtection * prot);

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
  SYSTEM_INFO si;

  GetSystemInfo (&si);

  return si.dwPageSize;
}

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &prot))
    return FALSE;

  return (prot & GUM_PAGE_READ) != 0;
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result;
  gsize offset;
  HANDLE self;
  gsize page_size;

  result = g_malloc (len);
  offset = 0;

  self = GetCurrentProcess ();
  page_size = gum_query_page_size ();

  while (offset != len)
  {
    const guint8 * chunk_address, * page_address;
    gsize page_offset, chunk_size;
    SIZE_T n;
    BOOL success;

    chunk_address = (const guint8 *) address + offset;
    page_address = GSIZE_TO_POINTER (
        GPOINTER_TO_SIZE (chunk_address) & ~(page_size - 1));
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

    success = ReadProcessMemory (self, chunk_address, result + offset,
        chunk_size, &n);
    if (!success)
      break;
    offset += n;
  }

  if (offset == 0)
  {
    g_free (result);
    result = NULL;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = offset;

  return result;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  return WriteProcessMemory (GetCurrentProcess (), address, bytes, len, NULL);
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection page_prot)
{
  DWORD win_page_prot, old_protect;

  win_page_prot = gum_page_protection_to_windows (page_prot);

  return VirtualProtect (address, size, win_page_prot, &old_protect);
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  FlushInstructionCache (GetCurrentProcess (), address, size);
}

gpointer
gum_try_alloc_n_pages (guint n_pages,
                       GumPageProtection page_prot)
{
  gpointer result;
  gsize page_size, size;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;

  result = gum_memory_allocate (NULL, size, page_size, page_prot);
  if (result != NULL && page_prot == GUM_PAGE_NO_ACCESS)
  {
    gum_memory_commit (result, size, page_prot);
  }

  return result;
}

gpointer
gum_try_alloc_n_pages_near (guint n_pages,
                            GumPageProtection page_prot,
                            const GumAddressSpec * address_spec)
{
  gpointer result = NULL;
  gsize page_size, size;
  DWORD win_page_prot;
  guint8 * low_address, * high_address;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;
  win_page_prot = gum_page_protection_to_windows (page_prot);

  low_address = (guint8 *)
      (GPOINTER_TO_SIZE (address_spec->near_address) & ~(page_size - 1));
  high_address = low_address;

  do
  {
    gsize cur_distance;

    low_address -= page_size;
    high_address += page_size;
    cur_distance = (gsize) high_address - (gsize) address_spec->near_address;
    if (cur_distance > address_spec->max_distance)
      break;

    result = VirtualAlloc (low_address, size, MEM_COMMIT | MEM_RESERVE,
        win_page_prot);
    if (result == NULL)
    {
      result = VirtualAlloc (high_address, size, MEM_COMMIT | MEM_RESERVE,
          win_page_prot);
    }
  }
  while (result == NULL);

  return result;
}

void
gum_query_page_allocation_range (gconstpointer mem,
                                 guint size,
                                 GumMemoryRange * range)
{
  range->base_address = GUM_ADDRESS (mem);
  range->size = size;
}

void
gum_free_pages (gpointer mem)
{
  BOOL success;

  success = VirtualFree (mem, 0, MEM_RELEASE);
  g_assert (success);
}

gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection page_prot)
{
  DWORD allocation_type, win_prot;
  gpointer base, aligned_base;
  gsize padded_size;
  gint retries = 3;

  allocation_type = (page_prot == GUM_PAGE_NO_ACCESS)
      ? MEM_RESERVE
      : MEM_RESERVE | MEM_COMMIT;

  win_prot = gum_page_protection_to_windows (page_prot);

  base = gum_virtual_alloc (address, size, allocation_type, win_prot);
  if (base == NULL)
    return NULL;

  aligned_base = GUM_ALIGN_POINTER (gpointer, base, alignment);
  if (aligned_base == base)
    return base;

  gum_memory_free (base, size);
  base = NULL;
  aligned_base = NULL;
  address = NULL;

  padded_size = size + (alignment - gum_query_page_size ());

  while (retries-- != 0)
  {
    base = gum_virtual_alloc (address, padded_size, allocation_type, win_prot);
    if (base == NULL)
      return NULL;

    gum_memory_free (base, padded_size);
    aligned_base = GUM_ALIGN_POINTER (gpointer, base, alignment);
    base = VirtualAlloc (aligned_base, size, allocation_type, win_prot);
    if (base != NULL)
      break;
  }

  return base;
}

static gpointer
gum_virtual_alloc (gpointer address,
                   gsize size,
                   DWORD allocation_type,
                   DWORD page_protection)
{
  gpointer result = NULL;

  if (address != NULL)
  {
    result = VirtualAlloc (address, size, allocation_type, page_protection);
  }

  if (result == NULL)
  {
    result = VirtualAlloc (NULL, size, allocation_type, page_protection);
  }

  return result;
}

gboolean
gum_memory_free (gpointer address,
                 gsize size)
{
  return VirtualFree (address, 0, MEM_RELEASE);
}

gboolean
gum_memory_release (gpointer address,
                    gsize size)
{
  return VirtualFree (address, size, MEM_DECOMMIT);
}

gboolean
gum_memory_commit (gpointer address,
                   gsize size,
                   GumPageProtection page_prot)
{
  return VirtualAlloc (address, size, MEM_COMMIT,
      gum_page_protection_to_windows (page_prot)) != NULL;
}

gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  return VirtualFree (address, size, MEM_DECOMMIT);
}

static gboolean
gum_memory_get_protection (gconstpointer address,
                           gsize len,
                           GumPageProtection * prot)
{
  gboolean success = FALSE;
  MEMORY_BASIC_INFORMATION mbi;

  if (prot == NULL)
  {
    GumPageProtection ignored_prot;

    return gum_memory_get_protection (address, len, &ignored_prot);
  }

  *prot = GUM_PAGE_NO_ACCESS;

  if (len > 1)
  {
    gsize page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = GPOINTER_TO_SIZE (address) & ~(page_size - 1);
    end_page = (GPOINTER_TO_SIZE (address) + len - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (GSIZE_TO_POINTER (start_page), 1,
        prot);

    for (cur_page = start_page + page_size;
        cur_page != end_page + page_size;
        cur_page += page_size)
    {
      GumPageProtection cur_prot;

      if (gum_memory_get_protection (GSIZE_TO_POINTER (cur_page), 1, &cur_prot))
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

  success = VirtualQuery (address, &mbi, sizeof (mbi)) != 0;
  if (success)
    *prot = gum_page_protection_from_windows (mbi.Protect);

  return success;
}

GumPageProtection
gum_page_protection_from_windows (DWORD native_prot)
{
  switch (native_prot & 0xff)
  {
    case PAGE_NOACCESS:
      return GUM_PAGE_NO_ACCESS;
    case PAGE_READONLY:
      return GUM_PAGE_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
      return GUM_PAGE_RW;
    case PAGE_EXECUTE:
      return GUM_PAGE_EXECUTE;
    case PAGE_EXECUTE_READ:
      return GUM_PAGE_RX;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return GUM_PAGE_RWX;
  }

  g_assert_not_reached ();
}

DWORD
gum_page_protection_to_windows (GumPageProtection page_prot)
{
  switch (page_prot)
  {
    case GUM_PAGE_NO_ACCESS:
      return PAGE_NOACCESS;
    case GUM_PAGE_READ:
      return PAGE_READONLY;
    case GUM_PAGE_READ | GUM_PAGE_WRITE:
      return PAGE_READWRITE;
    case GUM_PAGE_READ | GUM_PAGE_EXECUTE:
      return PAGE_EXECUTE_READ;
    case GUM_PAGE_EXECUTE | GUM_PAGE_READ | GUM_PAGE_WRITE:
      return PAGE_EXECUTE_READWRITE;
  }

#ifndef G_DISABLE_ASSERT
  g_assert_not_reached ();
#else
  abort ();
#endif
}
