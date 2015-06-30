/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_KERNEL_H__
#define __GUM_KERNEL_H__

#include <gum/gumprocess.h>

G_BEGIN_DECLS

GUM_API void gum_kernel_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
