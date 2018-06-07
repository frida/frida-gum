/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

gpointer
gum_kernel_alloc_n_pages (guint n_pages)
{
  (void) n_pages;

  return NULL;
}

gboolean
gum_kernel_try_mprotect (gpointer address,
                         gsize size,
                         GumPageProtection page_prot)
{
  (void) address;
  (void) size;
  (void) page_prot;

  return FALSE;
}

guint8 *
gum_kernel_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  (void) address;
  (void) len;
  (void) n_bytes_read;

  return NULL;
}

gboolean
gum_kernel_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  (void) address;
  (void) bytes;
  (void) len;

  return FALSE;
}

void
gum_kernel_enumerate_ranges (GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  (void) prot;
  (void) func;
  (void) user_data;
}

#endif

