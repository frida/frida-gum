/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#ifndef HAVE_DARWIN

gboolean
gum_kernel_api_is_available (void)
{
  return FALSE;
}

guint
gum_kernel_query_page_size (void)
{
  return 0;
}

GumAddress
gum_kernel_alloc_n_pages (guint n_pages)
{
  return 0;
}

void
gum_kernel_free_pages (GumAddress mem)
{
}

gboolean
gum_kernel_try_mprotect (GumAddress address,
                         gsize size,
                         GumPageProtection page_prot)
{
  return FALSE;
}

guint8 *
gum_kernel_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  return NULL;
}

gboolean
gum_kernel_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  return FALSE;
}

void
gum_kernel_scan (const GumMemoryRange * range,
                 const GumMatchPattern * pattern,
                 GumMemoryScanMatchFunc func,
                 gpointer user_data)
{
}

void
gum_kernel_enumerate_ranges (GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
}

void
gum_kernel_enumerate_module_ranges (const gchar * module_name,
                                    GumPageProtection prot,
                                    GumFoundKernelModuleRangeFunc func,
                                    gpointer user_data)
{
}

void
gum_kernel_enumerate_modules (GumFoundModuleFunc func,
                              gpointer user_data)
{
}

GumAddress
gum_kernel_find_base_address (void)
{
  return 0;
}

void
gum_kernel_set_base_address (GumAddress base)
{
}

#endif

