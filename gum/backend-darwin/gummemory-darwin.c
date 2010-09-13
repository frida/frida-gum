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

static vm_prot_t gum_page_protection_to_mach (GumPageProtection page_prot);

void
gum_memory_init (void)
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

void
gum_mprotect (gpointer address,
              guint size,
              GumPageProtection page_prot)
{
  gpointer aligned_address;
  vm_prot_t mach_page_prot;
  kern_return_t kr;

  g_assert (size != 0);

  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(gum_query_page_size () - 1));
  mach_page_prot = gum_page_protection_to_mach (page_prot);

  kr = vm_protect (mach_task_self (), (vm_address_t) aligned_address, size,
      FALSE, mach_page_prot);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
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
  vm_address_t result = 0;
  gsize page_size, size;
  kern_return_t kr;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;

  kr = vm_allocate (mach_task_self (), &result, size, TRUE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  gum_mprotect ((gpointer) result, size, page_prot);

  return (gpointer) result;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
{
  vm_address_t result = 0;
  gsize page_size, size;
  vm_address_t low_address, high_address;
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

    kr = vm_allocate (self, &low_address, size, FALSE);
    if (kr == KERN_SUCCESS)
    {
      result = low_address;
    }
    else
    {
      kr = vm_allocate (self, &high_address, size, FALSE);
      if (kr == KERN_SUCCESS)
        result = high_address;
    }
  }
  while (result == 0);

  g_assert (result != 0);

  gum_mprotect ((gpointer) result, size, page_prot);

  return (gpointer) result;
}

void
gum_free_pages (gpointer mem)
{
  mach_port_t self;
  vm_address_t address = 0;
  vm_size_t size = 0;
  vm_region_basic_info_data_t info;
  mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;
  memory_object_name_t obj;
  kern_return_t kr;

  self = mach_task_self ();

  kr = vm_region (self, &address, &size, VM_REGION_BASIC_INFO,
      (vm_region_info_t) &info, &info_count, &obj);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = vm_deallocate (self, address, size);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

static vm_prot_t
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
