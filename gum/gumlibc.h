/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LIBC_H__
#define __GUM_LIBC_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL gpointer gum_memset (gpointer dst, gint c, gsize n);
G_GNUC_INTERNAL gpointer gum_memcpy (gpointer dst, gconstpointer src, gsize n);
G_GNUC_INTERNAL gpointer gum_memmove (gpointer dst, gconstpointer src, gsize n);

G_END_DECLS

#endif
