/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#ifndef HAVE_DARWIN

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
                  guint8 * bytes,
                  gsize len)
{
  (void) address;
  (void) bytes;
  (void) len;

  return FALSE;
}

void
gum_kernel_enumerate_threads (GumFoundThreadFunc func,
                              gpointer user_data)
{
  (void) func;
  (void) user_data;
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

