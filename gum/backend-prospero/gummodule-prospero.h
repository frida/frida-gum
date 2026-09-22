/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_PROSPERO_H__
#define __GUM_MODULE_PROSPERO_H__

#include "gummodule.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_prospero_module_enumerate_exports (
    const gchar * path, GumFoundExportFunc func, gpointer user_data);
G_GNUC_INTERNAL void _gum_prospero_module_enumerate_symbols (
    const gchar * path, GumFoundSymbolFunc func, gpointer user_data);
G_GNUC_INTERNAL void _gum_prospero_module_enumerate_sections (
    const gchar * path, GumFoundSectionFunc func, gpointer user_data);

G_END_DECLS

#endif
