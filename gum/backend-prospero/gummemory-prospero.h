/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MEMORY_PROSPERO_H__
#define __GUM_MEMORY_PROSPERO_H__

#include "gummemory.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_prospero_make_code_readable (gconstpointer address,
    gsize size);

G_END_DECLS

#endif
