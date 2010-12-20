/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumdarwin.h"
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

#include <mach/mach.h>

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
  vm_size_t page_size;
  kern_return_t kr;

  kr = host_page_size (mach_host_self (), &page_size);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  return page_size;
}

gboolean
gum_memory_is_readable (gpointer address,
                        guint len)
{
  g_assert_not_reached (); /* FIXME */
}

guint8 *
gum_memory_read (gpointer address,
                 guint len,
                 gint * n_bytes_read)
{
  guint8 * result;
  mach_vm_size_t result_size = len;
  kern_return_t kr;

  result = g_malloc (len);

  kr = mach_vm_read_overwrite (mach_task_self (),
      (mach_vm_address_t) address, len, (vm_address_t) result, &result_size);
  if (kr == KERN_SUCCESS)
    *n_bytes_read = result_size;
  else
    *n_bytes_read = 0;

  return result;
}

void
gum_mprotect (gpointer address,
              guint size,
              GumPageProtection page_prot)
{
  guint page_size;
  gpointer aligned_address;
  guint aligned_size;
  vm_prot_t mach_page_prot;
  kern_return_t kr;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size = size;
  if (aligned_size % page_size != 0)
    aligned_size = (aligned_size + page_size) & ~(page_size - 1);
  mach_page_prot = gum_page_protection_to_mach (page_prot);

  kr = mach_vm_protect (mach_task_self (), (mach_vm_address_t) aligned_address,
      aligned_size, FALSE, mach_page_prot);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  g_usleep (G_USEC_PER_SEC / 1000);
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
  mach_vm_address_t result = 0;
  gsize page_size, size;
  kern_return_t kr;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;

  kr = mach_vm_allocate (mach_task_self (), &result, size, TRUE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  if (page_prot != GUM_PAGE_RW)
    gum_mprotect ((gpointer) result, size, page_prot);

  return (gpointer) result;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
{
  mach_vm_address_t result = 0;
  gsize page_size, size;
  mach_vm_address_t low_address, high_address;
  mach_port_t self;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;

  low_address =
      (GPOINTER_TO_SIZE (address_spec->near_address) & ~(page_size - 1));
  high_address = low_address;

  self = mach_task_self ();

  do
  {
    gsize cur_distance;
    kern_return_t kr;

    low_address -= page_size;
    high_address += page_size;
    cur_distance = (gsize) high_address - (gsize) address_spec->near_address;
    if (cur_distance > address_spec->max_distance)
      break;

    kr = mach_vm_allocate (self, &low_address, size, FALSE);
    if (kr == KERN_SUCCESS)
    {
      result = low_address;
    }
    else
    {
      kr = mach_vm_allocate (self, &high_address, size, FALSE);
      if (kr == KERN_SUCCESS)
        result = high_address;
    }
  }
  while (result == 0);

  g_assert (result != 0);

  if (page_prot != GUM_PAGE_RW)
    gum_mprotect ((gpointer) result, size, page_prot);

  return (gpointer) result;
}

void
gum_free_pages (gpointer mem)
{
  mach_port_t self;
  mach_vm_address_t address = (mach_vm_address_t) mem;
  mach_vm_size_t size = (mach_vm_size_t) 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t unused_port = MACH_PORT_NULL;
  kern_return_t kr;

  self = mach_task_self ();

  kr = mach_vm_region (self, &address, &size, VM_REGION_BASIC_INFO,
      (vm_region_info_t) &info, &info_count, &unused_port);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_vm_deallocate (self, address, size);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

GumPageProtection
gum_page_protection_from_mach (vm_prot_t native_prot)
{
  GumPageProtection page_prot = 0;

  if ((native_prot & VM_PROT_READ) == VM_PROT_READ)
    page_prot |= GUM_PAGE_READ;
  if ((native_prot & VM_PROT_WRITE) == VM_PROT_WRITE)
    page_prot |= GUM_PAGE_WRITE;
  if ((native_prot & VM_PROT_EXECUTE) == VM_PROT_EXECUTE)
    page_prot |= GUM_PAGE_EXECUTE;

  return page_prot;
}

vm_prot_t
gum_page_protection_to_mach (GumPageProtection page_prot)
{
  vm_prot_t mach_page_prot = VM_PROT_NONE;

  if ((page_prot & GUM_PAGE_READ) != 0)
    mach_page_prot |= VM_PROT_READ;
  if ((page_prot & GUM_PAGE_WRITE) != 0)
    mach_page_prot |= VM_PROT_WRITE | VM_PROT_COPY;
  if ((page_prot & GUM_PAGE_EXECUTE) != 0)
    mach_page_prot |= VM_PROT_EXECUTE;

  return mach_page_prot;
}
