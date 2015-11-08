/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_KERNEL_H__
#define __GUM_KERNEL_H__

#include <gum/gumprocess.h>

G_BEGIN_DECLS

GUM_API gboolean gum_kernel_api_is_available (void);
GUM_API guint8 * gum_kernel_read (GumAddress address, gsize len,
    gsize * n_bytes_read);
GUM_API gboolean gum_kernel_write (GumAddress address, const guint8 * bytes,
    gsize len);
GUM_API void gum_kernel_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);
GUM_API void gum_kernel_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
