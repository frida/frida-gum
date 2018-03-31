/*
 * Copyright (C) 2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_SCHEDULER_PRIV_H__
#define __GUM_SCRIPT_SCHEDULER_PRIV_H__

#include "gumscriptscheduler.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_script_scheduler_prepare_to_fork (void);
G_GNUC_INTERNAL void _gum_script_scheduler_recover_from_fork (void);

G_END_DECLS

#endif
