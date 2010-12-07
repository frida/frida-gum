/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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
#include "gumwindows.h"

static HANDLE _gum_memory_heap = INVALID_HANDLE_VALUE;

void
_gum_memory_init (void)
{
  ULONG heap_frag_value = 2;

  _gum_memory_heap = HeapCreate (HEAP_GENERATE_EXCEPTIONS, 0, 0);

  HeapSetInformation (_gum_memory_heap, HeapCompatibilityInformation,
      &heap_frag_value, sizeof (heap_frag_value));
}

void
_gum_memory_deinit (void)
{
  HeapDestroy (_gum_memory_heap);
  _gum_memory_heap = INVALID_HANDLE_VALUE;
}

guint
gum_query_page_size (void)
{
  SYSTEM_INFO si;
  GetSystemInfo (&si);
  return si.dwPageSize;
}

gboolean
gum_memory_is_readable (gpointer address,
                        guint len)
{
  MEMORY_BASIC_INFORMATION mbi;
  SIZE_T ret;

  ret = VirtualQuery (address, &mbi, sizeof (mbi));
  g_assert (ret != 0);

  /* FIXME: this will do for now: */
  g_assert ((guint8 *) address + len <=
      (guint8 *) mbi.BaseAddress + mbi.RegionSize);

  return (mbi.Protect == PAGE_READWRITE
      || mbi.Protect == PAGE_READONLY
      || mbi.Protect == PAGE_EXECUTE_READ
      || mbi.Protect == PAGE_EXECUTE_READWRITE);
}

guint8 *
gum_memory_read (gpointer address,
                 guint len,
                 gint * n_bytes_read)
{
  guint8 * result;
  SIZE_T number_of_bytes_read = 0;
  BOOL success;

  result = (guint8 *) g_malloc (len);

  success = ReadProcessMemory (GetCurrentProcess (), address, result, len,
      &number_of_bytes_read);
  if (success)
    *n_bytes_read = number_of_bytes_read;
  else
    *n_bytes_read = 0;

  return result;
}

gboolean
gum_memory_write (gpointer address,
                  guint8 * bytes,
                  guint len)
{
  return WriteProcessMemory (GetCurrentProcess (), address, bytes, len, NULL);
}

void
gum_mprotect (gpointer address,
              guint size,
              GumPageProtection page_prot)
{
  DWORD win_page_prot, old_protect;
  BOOL success;

  win_page_prot = gum_page_protection_to_windows (page_prot);
  success = VirtualProtect (address, size, win_page_prot, &old_protect);
  g_assert (success);
}

guint
gum_peek_private_memory_usage (void)
{
  guint total_size = 0;
  BOOL success;
  PROCESS_HEAP_ENTRY entry;

  success = HeapLock (_gum_memory_heap);
  g_assert (success);

  entry.lpData = NULL;
  while (HeapWalk (_gum_memory_heap, &entry) != FALSE)
  {
    if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0)
      total_size += entry.cbData;
  }

  success = HeapUnlock (_gum_memory_heap);
  g_assert (success);

  return total_size;
}

gpointer
gum_malloc (gsize size)
{
  return HeapAlloc (_gum_memory_heap, 0, size);
}

gpointer
gum_malloc0 (gsize size)
{
  return HeapAlloc (_gum_memory_heap, HEAP_ZERO_MEMORY, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  if (mem != NULL)
    return HeapReAlloc (_gum_memory_heap, 0, mem, size);
  else
    return gum_malloc (size);
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = gum_malloc (byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  BOOL success;

  success = HeapFree (_gum_memory_heap, 0, mem);
  g_assert (success);
}

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  guint size;
  DWORD win_page_prot;
  gpointer result;

  size = n_pages * gum_query_page_size ();
  win_page_prot = gum_page_protection_to_windows (page_prot);
  result = VirtualAlloc (NULL, size, MEM_COMMIT | MEM_RESERVE, win_page_prot);
  g_assert (result != NULL);

  return result;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
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

  g_assert (result != NULL);

  return result;
}

void
gum_free_pages (gpointer mem)
{
  BOOL success;

  success = VirtualFree (mem, 0, MEM_RELEASE);
  g_assert (success);
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

  g_assert_not_reached ();
  return PAGE_NOACCESS;
}