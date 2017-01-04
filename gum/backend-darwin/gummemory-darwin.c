/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumdarwin.h"
#include "gummemory-priv.h"

#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

typedef gboolean (* GumFoundFreeRangeFunc) (const GumMemoryRange * range,
    gpointer user_data);

typedef struct _GumAllocNearContext GumAllocNearContext;

struct _GumAllocNearContext
{
  gpointer result;
  gsize size;
  const GumAddressSpec * address_spec;
  mach_port_t task;
};

static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumMemoryRange * range, gpointer user_data);

guint
_gum_memory_backend_query_page_size (void)
{
  return getpagesize ();
}

gboolean
gum_darwin_query_page_size (mach_port_t task,
                            guint * page_size)
{
  int pid;
  kern_return_t kr;
  GumCpuType cpu_type;

  if (task == mach_task_self ())
  {
    *page_size = gum_query_page_size ();
    return TRUE;
  }

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
      *page_size = 4096;
      break;
    case GUM_CPU_ARM:
    {
      if (gum_darwin_is_ios9_or_newer ())
      {
        char buf[256];
        size_t size;
        int res;
        guint64 hw_page_size;

        size = sizeof (buf);
        res = sysctlbyname ("hw.pagesize", buf, &size, NULL, 0);
        g_assert_cmpint (res, ==, 0);

        if (size == 8)
          hw_page_size = *((guint64 *) buf);
        else if (size == 4)
          hw_page_size = *((guint32 *) buf);
        else
          g_assert_not_reached ();

        *page_size = hw_page_size;
      }
      else
      {
        *page_size = 4096;
      }

      break;
    }
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
  GumAddress prev_end = 0;

  self = mach_task_self ();

  while (TRUE)
  {
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr;

    kr = mach_vm_region_recurse (self, &address, &size, &depth,
        (vm_region_recurse_info_t) &info, &info_count);
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
  }
}

gboolean
gum_memory_is_readable (GumAddress address,
                        gsize len)
{
  gboolean is_readable;
  guint8 * bytes;
  gsize n_bytes_read;

  bytes = gum_memory_read (address, len, &n_bytes_read);
  is_readable = bytes != NULL && n_bytes_read == len;
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
                  const guint8 * bytes,
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
  guint page_size;
  guint8 * result;
  gsize offset;
  mach_port_t self;
  kern_return_t kr;

  if (!gum_darwin_query_page_size (task, &page_size))
    return NULL;

  if (address < page_size)
    return NULL;

  result = g_malloc (len);
  offset = 0;

  self = mach_task_self ();

  while (offset != len)
  {
    GumAddress chunk_address, page_address;
    gsize chunk_size, page_offset;

    chunk_address = address + offset;
    page_address = chunk_address & ~(GumAddress) (page_size - 1);
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

#ifdef HAVE_IOS
    mach_vm_size_t n_bytes_read;

    /* mach_vm_read corrupts memory on iOS */
    kr = mach_vm_read_overwrite (task, chunk_address, chunk_size,
        (vm_address_t) (result + offset), &n_bytes_read);
    if (kr != KERN_SUCCESS)
      break;
    g_assert_cmpuint (n_bytes_read, ==, chunk_size);
#else
    vm_offset_t result_data;
    mach_msg_type_number_t result_size;

    /* mach_vm_read_overwrite leaks memory on macOS */
    kr = mach_vm_read (task, page_address, page_size,
        &result_data, &result_size);
    if (kr != KERN_SUCCESS)
      break;
    g_assert_cmpuint (result_size, ==, page_size);
    memcpy (result + offset, (gpointer) (result_data + page_offset),
        chunk_size);
    mach_vm_deallocate (self, result_data, result_size);
#endif

    offset += chunk_size;
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
gum_darwin_write (mach_port_t task,
                  GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  guint page_size;
  kern_return_t kr;

  if (!gum_darwin_query_page_size (task, &page_size))
    return FALSE;

  if (address < page_size)
    return FALSE;

  kr = mach_vm_write (task, address, (vm_offset_t) bytes, len);

  return (kr == KERN_SUCCESS);
}

static kern_return_t
gum_mach_vm_protect (vm_map_t target_task,
                     mach_vm_address_t address,
                     mach_vm_size_t size,
                     boolean_t set_maximum,
                     vm_prot_t new_protection)
{
#if defined (HAVE_ARM)
  kern_return_t result;
  guint32 args[] = {
    target_task,
    address & 0xffffffff,
    (address >> 32) & 0xffffffff,
    size & 0xffffffff,
    (size >> 32) & 0xffffffff,
    set_maximum,
    new_protection,
    0
  };

  asm volatile (
      "push {r0, r1, r2, r3, r4, r5, r6, r7, r12}\n\t"
      "ldmdb %1!, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
      "mvn r12, 0xd\n\t"
      "svc 0x80\n\t"
      "mov %0, r0\n\t"
      "pop {r0, r1, r2, r3, r4, r5, r6, r7, r12}\n\t"
      : "=r" (result)
      : "r" (args + G_N_ELEMENTS (args))
      : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r12"
  );

  return result;
#elif defined (HAVE_ARM64)
  kern_return_t result;

  asm volatile (
      "sub sp, sp, #16 * 3\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x3, [sp, #16 * 1]\n\t"
      "stp x4, x16, [sp, #16 * 2]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x3, %4\n\t"
      "mov x4, %5\n\t"
      "movn x16, 0xd\n\t"
      "svc 0x80\n\t"
      "mov %w0, w0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x3, [sp, #16 * 1]\n\t"
      "ldp x4, x16, [sp, #16 * 2]\n\t"
      "add sp, sp, #16 * 3\n\t"
      : "=r" (result)
      : "r" ((gsize) target_task),
        "r" (address),
        "r" (size),
        "r" ((gsize) set_maximum),
        "r" ((gsize) new_protection)
      : "x0", "x1", "x2", "x3", "x4", "x16"
  );

  return result;
#else
  return mach_vm_protect (target_task, address, size, set_maximum,
      new_protection);
#endif
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

  kr = gum_mach_vm_protect (mach_task_self (),
      GPOINTER_TO_SIZE (aligned_address), aligned_size, FALSE, mach_page_prot);

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
gum_try_alloc_n_pages_near (guint n_pages,
                            GumPageProtection page_prot,
                            const GumAddressSpec * address_spec)
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
  if (ctx.result == NULL)
    return NULL;

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
