/*
 * Copyright (C) 2017-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_PRIV_H__
#define __GUM_PROCESS_PRIV_H__

#include "gumprocess.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_process_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);
G_GNUC_INTERNAL void _gum_process_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
G_GNUC_INTERNAL void _gum_process_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);

G_END_DECLS

#endif
