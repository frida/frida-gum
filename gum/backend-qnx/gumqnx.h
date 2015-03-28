/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QNX_H__
#define __GUM_QNX_H__

#include "gumprocess.h"

G_BEGIN_DECLS

GUM_API void gum_qnx_enumerate_ranges (pid_t pid, GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
