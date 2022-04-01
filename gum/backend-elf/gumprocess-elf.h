/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_ELF_H__
#define __GUM_PROCESS_ELF_H__

#include "gumprocess.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL gboolean _gum_process_resolve_module_name (const gchar * name,
    gchar ** path, GumAddress * base);

G_END_DECLS

#endif
