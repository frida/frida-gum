/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumsymbolutil.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

typedef const struct dyld_all_image_infos * (* DyldGetAllImageInfosFunc) (
    void);

static DyldGetAllImageInfosFunc get_all_image_infos_impl = NULL;

void
gum_symbol_util_init (void)
{
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  const struct dyld_all_image_infos * all_info;
  guint count, i;

  if (get_all_image_infos_impl == NULL)
  {
    void * syslib;

    syslib = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
    get_all_image_infos_impl = dlsym (syslib, "_dyld_get_all_image_infos");
    g_assert (get_all_image_infos_impl != NULL);
    dlclose (syslib);
  }

  all_info = get_all_image_infos_impl ();

  count = all_info->infoArrayCount;
  for (i = 0; i != count; i++)
  {
    const struct dyld_image_info * info = &all_info->infoArray[i];
    gchar * name;
    gboolean carry_on;

    name = g_path_get_basename (info->imageFilePath);
    carry_on = func (name, (gpointer) info->imageLoadAddress,
        info->imageFilePath, user_data);
    g_free (name);

    if (!carry_on)
      break;
  }
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  func ("badger_create", GUINT_TO_POINTER (0x1010), user_data);
  func ("badger_destroy", GUINT_TO_POINTER (0x1020), user_data);
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * export_name)
{
  return NULL;
}
