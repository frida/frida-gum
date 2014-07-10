/*
 * Copyright (C) 2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_LINUX_H__
#define __GUM_LINUX_H__

#include "gumprocess.h"

G_BEGIN_DECLS

GUM_API void gum_linux_enumerate_ranges (pid_t pid,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
