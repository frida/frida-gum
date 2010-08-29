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

void
gum_symbol_util_init (void)
{
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  func ("BadgerFoundation.dylib", GUINT_TO_POINTER (0x1000),
      "/usr/lib/libBadgerFoundation.dylib", user_data);
  func ("SnakeFoundation.dylib", GUINT_TO_POINTER (0x2000),
      "/usr/lib/libSnakeFoundation.dylib", user_data);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  if (g_str_has_prefix (module_name, "Badger"))
  {
    func ("badger_create", GUINT_TO_POINTER (0x1010), user_data);
    func ("badger_destroy", GUINT_TO_POINTER (0x1020), user_data);
  }
  else if (g_str_has_prefix (module_name, "Snake"))
  {
    func ("snake_create", GUINT_TO_POINTER (0x2010), user_data);
    func ("snake_destroy", GUINT_TO_POINTER (0x2020), user_data);
  }
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * export_name)
{
  return NULL;
}
