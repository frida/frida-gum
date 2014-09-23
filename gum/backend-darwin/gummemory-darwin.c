/*
 * Copyright (C) 2010-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumdarwin.h"
#include "gummemory-priv.h"

#include <libkern/OSCacheControl.h>
#include <mach/mach.h>

typedef gboolean (* GumFoundFreeRangeFunc) (const GumMemoryRange * range,
    gpointer user_data);

typedef struct _GumAllocNearContext GumAllocNearContext;

struct _GumAllocNearContext
{
  gpointer result;
  gsize size;
  GumAddressSpec * address_spec;
  mach_port_t task;
};

static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumMemoryRange * range, gpointer user_data);

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
gum_darwin_query_page_size (mach_port_t task,
                            guint * page_size)
{
  int pid;
  kern_return_t kr;
  GumCpuType cpu_type;

  /* FIXME: any way we can probe it without access to the task's host port? */
  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  if (!gum_darwin_cpu_type_from_pid (pid, &cpu_type))
    return FALSE;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM:
      *page_size = 4096;
      break;
    case GUM_CPU_ARM64:
      *page_size = 16384;
      break;
  }

  return TRUE;
}

static void
gum_memory_enumerate_free_ranges (GumFoundFreeRangeFunc func,
                                  gpointer user_data)
{
  mach_port_t self;
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  mach_vm_size_t size = (mach_vm_size_t) 0;
  natural_t depth = 0;
  GumAddress prev_end = 0;

  self = mach_task_self ();

  while (TRUE)
  {
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr;

    while (TRUE)
    {
      kr = mach_vm_region_recurse (self, &address, &size, &depth,
          (vm_region_recurse_info_t) &info, &info_count);
      if (kr != KERN_SUCCESS)
        break;

      if (info.is_submap)
      {
        depth++;
        continue;
      }
      else
      {
        break;
      }
    }

    if (kr != KERN_SUCCESS)
      break;

    if (prev_end != 0)
    {
      gint64 gap_size;

      gap_size = address - prev_end;

      if (gap_size > 0)
      {
        GumMemoryRange r;

        r.base_address = prev_end;
        r.size = gap_size;

        if (!func (&r, user_data))
          return;
      }
    }

    prev_end = address + size;

    address += size;
    size = 0;
  }
}

gboolean
gum_memory_is_readable (GumAddress address,
                        gsize len)
{
  gboolean is_readable;
  guint8 * bytes;

  bytes = gum_memory_read (address, len, NULL);
  is_readable = bytes != NULL;
  g_free (bytes);

  return is_readable;
}

guint8 *
gum_memory_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  return gum_darwin_read (mach_task_self (), address, len, n_bytes_read);
}

gboolean
gum_memory_write (GumAddress address,
                  guint8 * bytes,
                  gsize len)
{
  return gum_darwin_write (mach_task_self (), address, bytes, len);
}

guint8 *
gum_darwin_read (mach_port_t task,
                 GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result;
  mach_vm_size_t result_len = 0;
  kern_return_t kr;

  result = g_malloc (len);

  kr = mach_vm_read_overwrite (task, address, len,
      (vm_address_t) result, &result_len);

  if (kr != KERN_SUCCESS)
  {
    g_free (result);
    result = NULL;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = result_len;

  return result;
}

gboolean
gum_darwin_write (mach_port_t task,
                  GumAddress address,
                  guint8 * bytes,
                  gsize len)
{
  kern_return_t kr;

  kr = mach_vm_write (task, address, (vm_offset_t) bytes, len);

  return (kr == KERN_SUCCESS);
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection page_prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  vm_prot_t mach_page_prot;
  kern_return_t kr;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  mach_page_prot = gum_page_protection_to_mach (page_prot);

  kr = mach_vm_protect (mach_task_self (), GPOINTER_TO_SIZE (aligned_address),
      aligned_size, FALSE, mach_page_prot);

  return kr == KERN_SUCCESS;
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  sys_icache_invalidate (address, size);
  sys_dcache_flush (address, size);
}

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection page_prot)
{
  mach_vm_address_t result = 0;
  gsize page_size, size;
  kern_return_t kr;

  page_size = gum_query_page_size ();
  size = (1 + n_pages) * page_size;

  kr = mach_vm_allocate (mach_task_self (), &result, size, VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  *((gsize *) GSIZE_TO_POINTER (result)) = size;

  if (page_prot != GUM_PAGE_READ)
  {
    gum_mprotect (GSIZE_TO_POINTER (result), page_size, GUM_PAGE_READ);
  }

  if (page_prot != GUM_PAGE_RW)
  {
    gum_mprotect (GSIZE_TO_POINTER (result + page_size), size - page_size,
        page_prot);
  }

  return GSIZE_TO_POINTER (result + page_size);
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection page_prot,
                        GumAddressSpec * address_spec)
{
  gsize page_size;
  GumAllocNearContext ctx;

  page_size = gum_query_page_size ();

  ctx.result = NULL;
  ctx.size = (1 + n_pages) * gum_query_page_size ();
  ctx.address_spec = address_spec;
  ctx.task = mach_task_self ();

  gum_memory_enumerate_free_ranges (gum_try_alloc_in_range_if_near_enough,
      &ctx);

  g_assert (ctx.result != NULL);

  *((gsize *) ctx.result) = ctx.size;

  if (page_prot != GUM_PAGE_READ)
  {
    gum_mprotect (ctx.result, page_size, GUM_PAGE_READ);
  }

  if (page_prot != GUM_PAGE_RW)
  {
    gum_mprotect (ctx.result + page_size, ctx.size - page_size, page_prot);
  }

  return ctx.result + page_size;
}

static gboolean
gum_try_alloc_in_range_if_near_enough (const GumMemoryRange * range,
                                       gpointer user_data)
{
  GumAllocNearContext * ctx = user_data;
  GumAddress base_address;
  gsize distance;
  mach_vm_address_t address;
  kern_return_t kr;

  if (range->size < ctx->size)
    return TRUE;

  base_address = range->base_address;
  distance =
      ABS (ctx->address_spec->near_address - GSIZE_TO_POINTER (base_address));
  if (distance > ctx->address_spec->max_distance)
  {
    base_address = range->base_address + range->size - ctx->size;
    distance =
        ABS (ctx->address_spec->near_address - GSIZE_TO_POINTER (base_address));
  }

  if (distance > ctx->address_spec->max_distance)
    return TRUE;

  address = base_address;
  kr = mach_vm_allocate (ctx->task, &address, ctx->size, VM_FLAGS_FIXED);
  if (kr != KERN_SUCCESS)
    return TRUE;

  ctx->result = GSIZE_TO_POINTER (address);
  return FALSE;
}

void
gum_free_pages (gpointer mem)
{
  gsize page_size;
  mach_vm_address_t address;
  mach_vm_size_t size;
  kern_return_t kr;

  page_size = gum_query_page_size ();

  address = GPOINTER_TO_SIZE (mem) - page_size;
  size = *((gsize *) address);

  kr = mach_vm_deallocate (mach_task_self (), address, size);
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
