/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#include "gum-init.h"
#include "gumdarwin.h"

#include <mach/mach.h>

static mach_port_t gum_kernel_get_task (void);
static mach_port_t gum_kernel_do_init (void);
static void gum_kernel_do_deinit (void);

gboolean
gum_kernel_api_is_available (void)
{
  return gum_kernel_get_task () != MACH_PORT_NULL;
}

guint
gum_kernel_query_page_size (void)
{
  return vm_kernel_page_size;
}

gpointer
gum_kernel_alloc_n_pages (guint n_pages)
{
  mach_vm_address_t result;
  mach_port_t task;
  gsize page_size, size;
  kern_return_t kr;
  gboolean written;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return NULL;

  page_size = vm_kernel_page_size;
  size = (n_pages + 1) * page_size;

  result = 0;
  kr = mach_vm_allocate (task, &result, size, VM_FLAGS_ANYWHERE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  written = gum_darwin_write (task, result, (guint8 *) &size, sizeof (gsize));
  g_assert (written);

  kr = vm_protect (task, result + page_size, size - page_size,
      TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  return GSIZE_TO_POINTER (result + page_size);
}

gboolean
gum_kernel_try_mprotect (gpointer address,
                         gsize size,
                         GumPageProtection page_prot)
{
  mach_port_t task;
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  vm_prot_t mach_page_prot;
  kern_return_t kr;

  g_assert (size != 0);

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return FALSE;

  page_size = vm_kernel_page_size;
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  mach_page_prot = gum_page_protection_to_mach (page_prot);

  kr = mach_vm_protect (task, GPOINTER_TO_SIZE (aligned_address),
      aligned_size, FALSE, mach_page_prot);

  return kr == KERN_SUCCESS;
}

guint8 *
gum_kernel_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  mach_port_t task;
  guint page_size;
  guint8 * result;
  gsize offset;
  kern_return_t kr;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return NULL;

  /* Failsafe size, smaller than the kernel page size. */
  page_size = 2048;
  result = g_malloc (len);
  offset = 0;

  while (offset != len)
  {
    GumAddress chunk_address, page_address;
    gsize chunk_size, page_offset;

    chunk_address = address + offset;
    page_address = chunk_address & ~(GumAddress) (page_size - 1);
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

    mach_vm_size_t n_bytes_read;

    /* mach_vm_read corrupts memory on iOS */
    kr = mach_vm_read_overwrite (task, chunk_address, chunk_size,
        (vm_address_t) (result + offset), &n_bytes_read);
    if (kr != KERN_SUCCESS)
      break;
    g_assert_cmpuint (n_bytes_read, ==, chunk_size);

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
gum_kernel_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return FALSE;

  return gum_darwin_write (task, address, bytes, len);
}

void
gum_kernel_enumerate_ranges (GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  gum_darwin_enumerate_ranges (task, prot, func, user_data);
}

static mach_port_t
gum_kernel_get_task (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_kernel_do_init, NULL);

  return (mach_port_t) init_once.retval;
}

static mach_port_t
gum_kernel_do_init (void)
{
#ifdef HAVE_IOS
  mach_port_t task = MACH_PORT_NULL;

  task_for_pid (mach_task_self (), 0, &task);
  if (task == MACH_PORT_NULL)
  {
    /* Untested, but should work on iOS 9.1 with Pangu jailbreak */
    host_get_special_port (mach_host_self (), HOST_LOCAL_NODE, 4, &task);
  }

  if (task != MACH_PORT_NULL)
    _gum_register_destructor (gum_kernel_do_deinit);

  return task;
#else
  (void) gum_kernel_do_deinit;

  return MACH_PORT_NULL;
#endif
}

static void
gum_kernel_do_deinit (void)
{
  mach_port_deallocate (mach_task_self (), gum_kernel_get_task ());
}
