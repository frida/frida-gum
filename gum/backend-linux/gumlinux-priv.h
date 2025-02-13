/*
 * Copyright (C) 2022-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LINUX_PRIV_H__
#define __GUM_LINUX_PRIV_H__

#include <dlfcn.h>
#include <glib.h>
#include <unistd.h>

G_BEGIN_DECLS

typedef struct _GumProcMapsIter GumProcMapsIter;

struct _GumProcMapsIter
{
  gint fd;
  gchar buffer[(2 * PATH_MAX) + 1];
  gchar * read_cursor;
  gchar * write_cursor;
};

G_GNUC_INTERNAL const Dl_info * _gum_process_get_libc_info (void);

G_GNUC_INTERNAL void gum_proc_maps_iter_init_for_self (GumProcMapsIter * iter);
G_GNUC_INTERNAL void gum_proc_maps_iter_init_for_pid (GumProcMapsIter * iter,
    pid_t pid);
G_GNUC_INTERNAL void gum_proc_maps_iter_destroy (GumProcMapsIter * iter);

G_GNUC_INTERNAL gboolean gum_proc_maps_iter_next (GumProcMapsIter * iter,
    const gchar ** line);

G_GNUC_INTERNAL gboolean _gum_try_translate_vdso_name (gchar * name);

G_GNUC_INTERNAL void _gum_acquire_dumpability (void);
G_GNUC_INTERNAL void _gum_release_dumpability (void);

G_END_DECLS

#endif
