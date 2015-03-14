/*
 * Copyright (C) 2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LINUX_H__
#define __GUM_LINUX_H__

#include "gumprocess.h"

G_BEGIN_DECLS

GumCpuType gum_linux_cpu_type_from_file (const gchar * path, GError ** error);
GumCpuType gum_linux_cpu_type_from_pid (pid_t pid, GError ** error);
GUM_API void gum_linux_enumerate_ranges (pid_t pid,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
