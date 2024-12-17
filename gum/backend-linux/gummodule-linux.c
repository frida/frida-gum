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
gum_module_find (const gchar * module_name)
{
#if defined (HAVE_MUSL)
  struct link_map * cur;

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    if (gum_linux_module_path_matches (cur->l_name, module_name))
      return _gum_module_make (cur, NULL, cur->l_name);
  }

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    gchar * target, * parent_dir, * canonical_path;
    gboolean is_match;

    target = g_file_read_link (cur->l_name, NULL);
    if (target == NULL)
      continue;
    parent_dir = g_path_get_dirname (cur->l_name);
    canonical_path = g_canonicalize_filename (target, parent_dir);

    is_match = gum_linux_module_path_matches (canonical_path, module_name);

    g_free (canonical_path);
    g_free (parent_dir);
    g_free (target);

    if (is_match)
      return _gum_module_make (cur, NULL, cur->l_name);
  }

  return NULL;
#else
# if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return gum_android_find_module (module_name);
# endif

  return _gum_module_make (dlopen (module_name, RTLD_LAZY | RTLD_NOLOAD),
      (GDestroyNotify) dlclose, module_name);
#endif
}

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  GumModule * module;
  GumGenericDlopenImpl dlopen_impl = dlopen;
  gpointer handle;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  module = gum_module_find (module_name);
  if (module != NULL)
    return module;

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlopen (&dlopen_impl);
#endif

  handle = dlopen_impl (module_name, RTLD_LAZY);
  if (handle == NULL)
    goto not_found;

  return _gum_module_make (handle, (GDestroyNotify) dlclose, module_name);

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (GumModule * self)
{
  gpointer handle;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return TRUE;
#endif

#ifndef HAVE_MUSL
  handle = dlopen (self->path, RTLD_LAZY);
  if (handle == NULL)
    return FALSE;
  dlclose (handle);
#endif

  return TRUE;
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
