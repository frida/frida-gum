/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-elf.h"

#include "gum/gumandroid.h"

#include <dlfcn.h>

static GumAddress gum_dlsym (gpointer module_handle, const gchar * symbol_name);

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  GumModule * module;
  GumGenericDlopenImpl dlopen_impl = dlopen;
  gpointer handle;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  module = gum_process_find_module_by_name (module_name);
  if (module != NULL)
    return module;

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlopen (&dlopen_impl);
#endif

  handle = dlopen_impl (module_name, RTLD_LAZY);
  if (handle == NULL)
    goto not_found;

  module = gum_process_find_module_by_name (module_name);
  g_assert (module != NULL);

  dlclose (handle);

  return module;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

void
gum_module_ensure_initialized (GumModule * self)
{
  gpointer handle;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return;
#endif

#ifndef HAVE_MUSL
  handle = dlopen (self->path, RTLD_LAZY);
  g_clear_pointer (&handle, dlclose);
#endif
}

void
gum_module_enumerate_exports (GumModule * self,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
#ifdef HAVE_ANDROID
  if (gum_android_is_linker_module_name (self->path))
  {
    const gchar ** magic_exports;
    guint i;

    magic_exports = gum_android_get_magic_linker_export_names ();

    for (i = 0; magic_exports[i] != NULL; i++)
    {
      const gchar * name = magic_exports[i];
      GumExportDetails d;

      d.type = GUM_EXPORT_FUNCTION;
      d.name = name;
      d.address = gum_module_find_export_by_name (self, name);
      g_assert (d.address != 0);

      if (!func (&d, user_data))
        return;
    }
  }
#endif

  _gum_module_enumerate_exports (self, func, user_data);
}

GumAddress
gum_module_find_export_by_name (GumModule * self,
                                const gchar * symbol_name)
{
#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  GumAddress address;

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE &&
      gum_android_try_resolve_magic_export (self->path, symbol_name, &address))
    return address;
#endif

  return gum_dlsym (self->handle, symbol_name);
}

GumAddress
gum_module_find_global_export_by_name (const gchar * symbol_name)
{
  return gum_dlsym (RTLD_DEFAULT, symbol_name);
}

static GumAddress
gum_dlsym (gpointer module_handle,
           const gchar * symbol_name)
{
  GumGenericDlsymImpl dlsym_impl = dlsym;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlsym (&dlsym_impl);
#endif

  return GUM_ADDRESS (dlsym_impl (module_handle, symbol_name));
}
