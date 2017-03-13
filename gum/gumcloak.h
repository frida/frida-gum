/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CLOAK_H__
#define __GUM_CLOAK_H__

#include <gum/gummemory.h>
#include <gum/gumprocess.h>

G_BEGIN_DECLS

GUM_API void gum_cloak_add_thread (GumThreadId id);
GUM_API void gum_cloak_remove_thread (GumThreadId id);
GUM_API gboolean gum_cloak_has_thread (GumThreadId id);

GUM_API void gum_cloak_add_range (const GumMemoryRange * range);
GUM_API void gum_cloak_remove_range (const GumMemoryRange * range);
GUM_API GArray * gum_cloak_clip_range (const GumMemoryRange * range);

G_END_DECLS

#endif
