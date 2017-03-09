/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CLOAK_H__
#define __GUM_CLOAK_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

GUM_API void gum_cloak_add_base_address (GumAddress base_address);
GUM_API void gum_cloak_remove_base_address (GumAddress base_address);
GUM_API gboolean gum_cloak_has_base_address (GumAddress base_address);

G_END_DECLS

#endif
