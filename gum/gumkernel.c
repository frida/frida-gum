/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#ifndef HAVE_DARWIN

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

