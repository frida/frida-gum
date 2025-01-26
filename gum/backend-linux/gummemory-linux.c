/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Kenjiro Ichise <ichise@doranekosystems.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumlinux-priv.h"
#include "gummemory-priv.h"
#include "gum/gumlinux.h"
#include "valgrind.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_SYS_PROCESS_VM_READV   347
# define GUM_SYS_PROCESS_VM_WRITEV  348
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define GUM_SYS_PROCESS_VM_READV   310
# define GUM_SYS_PROCESS_VM_WRITEV  311
#elif defined (HAVE_ARM)
# define GUM_SYS_PROCESS_VM_READV   (__NR_SYSCALL_BASE + 376)
# define GUM_SYS_PROCESS_VM_WRITEV  (__NR_SYSCALL_BASE + 377)
#elif defined (HAVE_ARM64)
# define GUM_SYS_PROCESS_VM_READV   270
# define GUM_SYS_PROCESS_VM_WRITEV  271
#elif defined (HAVE_MIPS)
# if _MIPS_SIM == _MIPS_SIM_ABI32
#  define GUM_SYS_PROCESS_VM_READV  (__NR_Linux + 345)
#  define GUM_SYS_PROCESS_VM_WRITEV (__NR_Linux + 346)
# elif _MIPS_SIM == _MIPS_SIM_ABI64
#  define GUM_SYS_PROCESS_VM_READV  (__NR_Linux + 304)
#  define GUM_SYS_PROCESS_VM_WRITEV (__NR_Linux + 305)
# elif _MIPS_SIM == _MIPS_SIM_NABI32
#  define GUM_SYS_PROCESS_VM_READV  (__NR_Linux + 309)
#  define GUM_SYS_PROCESS_VM_WRITEV (__NR_Linux + 310)
# else
#  error Unexpected MIPS ABI
# endif
#else
# error FIXME
#endif

static gboolean gum_memory_get_protection (gconstpointer address, gsize n,
    gsize * size, GumPageProtection * prot);

static gssize gum_libc_process_vm_readv (pid_t pid, const struct iovec * local,
    gulong num_local, const struct iovec * remote, gulong num_remote,
    gulong flags);
static gssize gum_libc_process_vm_writev (pid_t pid, const struct iovec * local,
    gulong num_local, const struct iovec * remote, gulong num_remote,
    gulong flags);

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_READ) != 0;
}

static gboolean
gum_memory_is_writable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_WRITE) != 0;
}

gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  gsize size;

  if (!gum_memory_get_protection (address, 1, &size, prot))
    return FALSE;

  return size >= 1;
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result = NULL;
  gsize result_len = 0;
  static gboolean kernel_feature_likely_enabled = TRUE;
  gboolean still_pending = TRUE;

  if (kernel_feature_likely_enabled && gum_linux_check_kernel_version (3, 2, 0))
  {
    gssize n;
    struct iovec local = {
      .iov_base = g_malloc (len),
      .iov_len = len
    };
    struct iovec remote = {
      .iov_base = (void *) address,
      .iov_len = len
    };

    n = gum_libc_process_vm_readv (getpid (), &local, 1, &remote, 1, 0);
    if (n > 0)
    {
      result_len = n;
      result = local.iov_base;
      if (result_len != len)
        result = g_realloc (result, result_len);
    }
    else
    {
      g_free (local.iov_base);
    }

    if (n == -1 && errno == ENOSYS)
      kernel_feature_likely_enabled = FALSE;
    else
      still_pending = FALSE;
  }

  if (still_pending)
  {
    gsize size;
    GumPageProtection prot;

    if (gum_memory_get_protection (address, len, &size, &prot) &&
        (prot & GUM_PAGE_READ) != 0)
    {
      result_len = MIN (len, size);
      result = g_memdup (address, result_len);
    }
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = result_len;

  return result;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  gboolean success = FALSE;
  static gboolean kernel_feature_likely_enabled = TRUE;
  gboolean still_pending = TRUE;

  if (kernel_feature_likely_enabled && gum_linux_check_kernel_version (3, 2, 0))
  {
    gssize n;
    struct iovec local = {
      .iov_base = (void *) bytes,
      .iov_len = len
    };
    struct iovec remote = {
      .iov_base = address,
      .iov_len = len
    };

    n = gum_libc_process_vm_writev (getpid (), &local, 1, &remote, 1, 0);
    if (n > 0)
      success = n == len;

    if (n == -1 && errno == ENOSYS)
      kernel_feature_likely_enabled = FALSE;
    else
      still_pending = FALSE;
  }

  if (still_pending)
  {
    if (gum_memory_is_writable (address, len))
    {
      memcpy (address, bytes, len);
      success = TRUE;
    }
  }

  return success;
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  gint posix_prot;
  gint result;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  posix_prot = _gum_page_protection_to_posix (prot);

  result = mprotect (aligned_address, aligned_size, posix_prot);

  return result == 0;
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
#if defined (HAVE_ANDROID) && defined (HAVE_ARM)
  cacheflush (GPOINTER_TO_SIZE (address), GPOINTER_TO_SIZE (address + size), 0);
#elif defined (HAVE_ARM) || defined (HAVE_ARM64) || defined (HAVE_MIPS)
# if defined (HAVE_CLEAR_CACHE)
  __builtin___clear_cache (address, address + size);
# elif defined (HAVE_ARM) && !defined (__ARM_EABI__)
  register gpointer r0 asm ("r0") = address;
  register gpointer r1 asm ("r1") = address + size;
  register      int r2 asm ("r2") = 0;

  asm volatile (
      "swi %[syscall]\n\t"
      : "+r" (r0)
      : "r" (r1),
        "r" (r2),
        [syscall] "i" (__ARM_NR_cacheflush)
      : "memory"
  );
# else
#  error Please implement for your architecture
# endif
#endif

  VALGRIND_DISCARD_TRANSLATIONS (address, size);
}

static gboolean
gum_memory_get_protection (gconstpointer address,
                           gsize n,
                           gsize * size,
                           GumPageProtection * prot)
{
  gboolean success;
  GumProcMapsIter iter;
  const gchar * line;

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
    gsize page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = GPOINTER_TO_SIZE (address) & ~(page_size - 1);
    end_page = (GPOINTER_TO_SIZE (address) + n - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (GSIZE_TO_POINTER (start_page), 1, NULL,
        prot);
    if (success)
    {
      *size = page_size - (GPOINTER_TO_SIZE (address) - start_page);
      for (cur_page = start_page + page_size;
          cur_page != end_page + page_size;
          cur_page += page_size)
      {
        GumPageProtection cur_prot;

        if (gum_memory_get_protection (GSIZE_TO_POINTER (cur_page), 1, NULL,
            &cur_prot) && (cur_prot != GUM_PAGE_NO_ACCESS ||
            *prot == GUM_PAGE_NO_ACCESS))
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

  gum_proc_maps_iter_init_for_self (&iter);

  while (gum_proc_maps_iter_next (&iter, &line))
  {
    gpointer start, end;
    gchar protection[4 + 1];

    sscanf (line, "%p-%p %s ", &start, &end, protection);

    if (start > address)
      break;
    else if (address >= start && address + n - 1 < end)
    {
      success = TRUE;
      *size = 1;
      if (protection[0] == 'r')
        *prot |= GUM_PAGE_READ;
      if (protection[1] == 'w')
        *prot |= GUM_PAGE_WRITE;
      if (protection[2] == 'x')
        *prot |= GUM_PAGE_EXECUTE;
      break;
    }
  }

  gum_proc_maps_iter_destroy (&iter);

  return success;
}

static gssize
gum_libc_process_vm_readv (pid_t pid,
                           const struct iovec * local,
                           gulong num_local,
                           const struct iovec * remote,
                           gulong num_remote,
                           gulong flags)
{
  return syscall (GUM_SYS_PROCESS_VM_READV, pid, local, num_local, remote,
      num_remote, flags);
}

static gssize
gum_libc_process_vm_writev (pid_t pid,
                            const struct iovec * local,
                            gulong num_local,
                            const struct iovec * remote,
                            gulong num_remote,
                            gulong flags)
{
  return syscall (GUM_SYS_PROCESS_VM_WRITEV, pid, local, num_local, remote,
      num_remote, flags);
}
