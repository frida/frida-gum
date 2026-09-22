/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_PROSPERO_H__
#define __GUM_PROCESS_PROSPERO_H__

#include "gumprocess.h"

#include <ucontext.h>
#include <sys/ptrace.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL int _gum_prospero_ptrace (int request, pid_t pid,
    caddr_t addr, int data);
G_GNUC_INTERNAL gboolean _gum_prospero_modify_current_thread (
    GumThreadId thread_id, GumModifyThreadFunc func, gpointer user_data);
G_GNUC_INTERNAL GumThreadDetails * _gum_prospero_find_thread_by_id (
    GumThreadId thread_id, GumThreadFlags flags);
G_GNUC_INTERNAL void _gum_prospero_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data, GumThreadFlags flags);

G_END_DECLS

#endif
