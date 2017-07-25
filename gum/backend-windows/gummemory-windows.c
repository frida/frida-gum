/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gumwindows.h"

static gpointer gum_virtual_alloc (gsize size, DWORD allocation_type,
    GumPageProtection page_prot, gpointer hint);

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

static gboolean
gum_memory_get_protection (GumAddress address,
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

  success = VirtualQuery (GSIZE_TO_POINTER (address), &mbi, sizeof (mbi)) != 0;
  if (success)
    *prot = gum_page_protection_from_windows (mbi.Protect);

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

guint8 *
gum_memory_read (GumAddress address,
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
    GumAddress chunk_address, page_address;
    gsize chunk_size, page_offset;
    SIZE_T n;
    BOOL success;

    chunk_address = address + offset;
    page_address = chunk_address & ~(page_size - 1);
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

    success = ReadProcessMemory (self, GSIZE_TO_POINTER (chunk_address),
        result + offset, chunk_size, &n);
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
gum_memory_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  return WriteProcessMemory (GetCurrentProcess (), GSIZE_TO_POINTER (address),
      bytes, len, NULL);
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
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  guint size;
  DWORD win_page_prot;
  gpointer result;

  size = n_pages * gum_query_page_size ();
  win_page_prot = gum_page_protection_to_windows (page_prot);

  result = gum_memory_allocate (size, page_prot, NULL);
  g_assert (result != NULL);

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
gum_free_pages (gpointer mem)
{
  BOOL success;

  success = VirtualFree (mem, 0, MEM_RELEASE);
  g_assert (success);
}

gpointer
gum_memory_allocate (gsize size,
                     GumPageProtection page_prot,
                     gpointer hint)
{
  return gum_virtual_alloc (size, MEM_COMMIT | MEM_RESERVE, page_prot, hint);
}

gpointer
gum_memory_reserve (gsize size,
                    gpointer hint)
{
  return gum_virtual_alloc (size, MEM_RESERVE, GUM_PAGE_NO_ACCESS, hint);
}

static gpointer
gum_virtual_alloc (gsize size,
                   DWORD allocation_type,
                   GumPageProtection page_prot,
                   gpointer hint)
{
  gpointer result = NULL;
  DWORD win_page_prot;
  static BOOL use_aslr = -1;

  win_page_prot = gum_page_protection_to_windows (page_prot);

  /* Replicate V8's behavior: only use ASLR on 64-bit systems. */
#if GLIB_SIZEOF_VOID_P == 4
  if (use_aslr == -1 && !IsWow64Process (GetCurrentProcess (), &use_aslr))
    use_aslr = FALSE;
#else
  use_aslr = TRUE;
#endif

  if (use_aslr &&
      (page_prot == GUM_PAGE_NO_ACCESS || page_prot == GUM_PAGE_RWX))
  {
    result = VirtualAlloc (hint, size, allocation_type, win_page_prot);
  }

  if (result == NULL)
  {
    result = VirtualAlloc (NULL, size, allocation_type, win_page_prot);
  }

  return result;
}

gboolean
gum_memory_commit (gpointer base,
                   gsize size,
                   GumPageProtection page_prot)
{
  DWORD win_page_prot;

  win_page_prot = gum_page_protection_to_windows (page_prot);

  return VirtualAlloc (base, size, MEM_COMMIT, win_page_prot) != NULL;
}

gboolean
gum_memory_uncommit (gpointer base,
                     gsize size)
{
  return VirtualFree (base, size, MEM_DECOMMIT);
}

gboolean
gum_memory_release_partial (gpointer base,
                            gsize size,
                            gpointer free_start,
                            gsize free_size)
{
  return VirtualFree (free_start, free_size, MEM_DECOMMIT);
}

gboolean
gum_memory_release (gpointer base,
                    gsize size)
{
  return VirtualFree (base, 0, MEM_RELEASE);
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
}
