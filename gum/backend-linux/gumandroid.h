/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ANDROID_H__
#define __GUM_ANDROID_H__

#include "gumelfmodule.h"
#include "gumprocess.h"

G_BEGIN_DECLS

typedef struct _GumAndroidUnrestrictedLinkerApi GumAndroidUnrestrictedLinkerApi;

typedef void * (* GumGenericDlopenImpl) (const char * path, int mode);
typedef void * (* GumGenericDlsymImpl) (void * handle, const char * symbol);

typedef void * (* GumAndroidDlopenImpl) (const char * path, int mode,
    void * caller);
typedef void * (* GumAndroidDlsymImpl) (void * handle, const char * symbol,
    const char * version, const void * caller_addr);

struct _GumAndroidUnrestrictedLinkerApi
{
  GumAndroidDlopenImpl dlopen;
  GumAndroidDlsymImpl dlsym;
};

GUM_API GumElfModule * gum_android_open_linker_module (void);
GUM_API void * gum_android_get_module_handle (const gchar * name);
GUM_API gboolean gum_android_ensure_module_initialized (const gchar * name);
GUM_API void gum_android_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
GUM_API gboolean gum_android_find_unrestricted_dlopen (
    GumGenericDlopenImpl * generic_dlopen);
GUM_API gboolean gum_android_find_unrestricted_dlsym (
    GumGenericDlsymImpl * generic_dlsym);
GUM_API gboolean gum_android_find_unrestricted_linker_api (
    GumAndroidUnrestrictedLinkerApi * api);

G_END_DECLS

#endif
