/*
 * Copyright (C) 2008-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_PROCESS_H__
#define __GUM_PROCESS_H__

#include <gum/gummemory.h>

G_BEGIN_DECLS

typedef gboolean (* GumFoundModuleFunc) (const gchar * name, GumAddress address,
    const gchar * path, gpointer user_data);
typedef gboolean (* GumFoundExportFunc) (const gchar * name, GumAddress address,
    gpointer user_data);
typedef gboolean (* GumFoundRangeFunc) (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

GUM_API void gum_process_enumerate_modules (GumFoundModuleFunc func,
    gpointer user_data);
GUM_API void gum_process_enumerate_ranges (GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_ranges (const gchar * module_name,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API GumAddress gum_module_find_base_address (const gchar * module_name);
GUM_API GumAddress gum_module_find_export_by_name (const gchar * module_name,
    const gchar * symbol_name);

G_END_DECLS

#endif
