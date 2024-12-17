/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_H__
#define __GUM_MODULE_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

#define GUM_TYPE_MODULE (gum_module_get_type ())
GUM_DECLARE_FINAL_TYPE (GumModule, gum_module, GUM, MODULE, GObject)

GUM_API GumModule * gum_module_find (const gchar * module_name);
GUM_API GumModule * gum_module_load (const gchar * module_name,
    GError ** error);

GUM_API const gchar * gum_module_get_name (GumModule * self);
GUM_API const gchar * gum_module_get_path (GumModule * self);
GUM_API const GumMemoryRange * gum_module_get_range (GumModule * self);

GUM_API void gum_module_ensure_initialized (GumModule * self);
GUM_API void gum_module_enumerate_imports (GumModule * self,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_exports (GumModule * self,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_symbols (GumModule * self,
    GumFoundSymbolFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_ranges (GumModule * self,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_sections (GumModule * self,
    GumFoundSectionFunc func, gpointer user_data);
GUM_API void gum_module_enumerate_dependencies (GumModule * self,
    GumFoundDependencyFunc func, gpointer user_data);
GUM_API GumAddress gum_module_find_export_by_name (GumModule * self,
    const gchar * symbol_name);
GUM_API GumAddress gum_module_find_global_export_by_name (
    const gchar * symbol_name);
GUM_API GumAddress gum_module_find_symbol_by_name (GumModule * self,
    const gchar * symbol_name);

G_END_DECLS

#endif
