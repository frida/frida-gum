/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ANDROID_H__
#define __GUM_ANDROID_H__

#include "gumprocess.h"

G_BEGIN_DECLS

typedef void * (* GumGenericDlopenImpl) (const char * path, int mode);
typedef void * (* GumAndroidDlopenImpl) (const char * path, int mode,
    void * caller);

G_GNUC_INTERNAL gboolean gum_android_is_linker_module_name (const gchar * name);
G_GNUC_INTERNAL GumModuleDetails * gum_android_get_linker_module (void);
G_GNUC_INTERNAL gboolean gum_android_find_unrestricted_dlopen (
    GumGenericDlopenImpl * generic_dlopen,
    GumAndroidDlopenImpl * android_dlopen);

G_END_DECLS

#endif
