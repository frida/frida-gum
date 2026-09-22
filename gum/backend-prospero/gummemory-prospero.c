/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory-prospero.h"

void
_gum_prospero_make_code_readable (gconstpointer address,
                                  gsize size)
{
  gum_try_mprotect ((gpointer) address, size, GUM_PAGE_RWX);
}
