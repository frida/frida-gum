/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_ELF_H__
#define __GUM_MODULE_ELF_H__

#include "gumelfmodule.h"
#include "gummodule.h"

G_BEGIN_DECLS

struct _GumModule
{
#ifndef GUM_DIET
  GObject parent;
#else
  GumObject parent;
#endif

  gpointer handle;
  GDestroyNotify destroy_handle;

  gchar * name;
  gchar * path;
  GumMemoryRange range;

  GumElfModule * elf_module;
};

G_GNUC_INTERNAL GumModule * _gum_module_make (gpointer handle,
    GDestroyNotify destroy_handle, const gchar * path);
G_GNUC_INTERNAL void _gum_module_enumerate_exports (GumModule * self,
    GumFoundExportFunc func, gpointer user_data);

G_GNUC_INTERNAL gboolean _gum_process_resolve_module_name (const gchar * name,
    gchar ** path, GumAddress * base);

G_END_DECLS

#endif
