/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-elf.h"

#include "gum/gumandroid.h"

#include <dlfcn.h>

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  GumModule * module;
  gpointer handle;

  /* Check if module is already loaded before attempting to load it */
  module = gum_process_find_module_by_name (module_name);
  if (module != NULL)
    return module;

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlopen (&dlopen_impl);
#endif

  if (handle == NULL)
    goto not_found;

  module = gum_process_find_module_by_name (module_name);
  g_assert (module != NULL);

  return module;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gchar *
_gum_native_module_find_path_by_address (GumAddress address)
{
  Dl_info info;

  if (dladdr (GSIZE_TO_POINTER (address), &info) == 0)
    return NULL;

  return g_strdup (info.dli_fname);
}
