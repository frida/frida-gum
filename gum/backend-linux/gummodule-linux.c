/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-elf.h"

#include "gum/gumandroid.h"

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
  {
    return _gum_module_make (gum_android_get_module_handle (module_name), NULL,
        module_name);
  }
# endif

  return _gum_module_make (dlopen (module_name, RTLD_LAZY | RTLD_NOLOAD),
      dlclose);
#endif
}

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  GumGenericDlopenImpl dlopen_impl = dlopen;
  gpointer handle;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  handle = gum_module_get_handle (module_name);
  if (handle != NULL)
    return g_object_new (GUM_TYPE_MODULE, "handle", handle, NULL);

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlopen (&dlopen_impl);
#endif

  handle = dlopen_impl (module_name, RTLD_LAZY);
  if (handle == NULL)
    goto not_found;

  return g_object_new (GUM_TYPE_MODULE, "handle", handle, NULL);

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (GumModule * self)
{
  gpointer module;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return gum_android_ensure_module_initialized (self->path);
#endif

#ifndef HAVE_MUSL
  module = dlopen (self->path, RTLD_LAZY);
  if (module == NULL)
    return FALSE;
  dlclose (module);
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
  GumAddress result;
  gpointer handle;
  GumGenericDlsymImpl dlsym_impl = dlsym;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE &&
      gum_android_try_resolve_magic_export (self->path, symbol_name, &result))
    return result;
#endif

  handle = (self != NULL) ? self->handle : RTLD_DEFAULT;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlsym (&dlsym_impl);
#endif

  result = GUM_ADDRESS (dlsym_impl (handle, symbol_name));

  return result;
}
