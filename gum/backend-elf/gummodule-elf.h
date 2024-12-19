/*
 * Copyright (C) 2022-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_ELF_H__
#define __GUM_MODULE_ELF_H__

#include "gumelfmodule.h"
#include "gummodule.h"

G_BEGIN_DECLS

typedef gpointer (* GumCreateModuleHandleFunc) (GumModule * module,
    gpointer user_data);

struct _GumModule
{
#ifndef GUM_DIET
  GObject parent;
#else
  GumObject parent;
#endif

  gchar * name;
  gchar * path;
  GumMemoryRange range;
  GumCreateModuleHandleFunc create_handle;
  gpointer create_handle_data;
  GDestroyNotify create_handle_data_destroy;
  GDestroyNotify destroy_handle;

  GMutex mutex;
  gpointer cached_handle;
  gboolean tried_create_handle;
  GumElfModule * elf_module;
};

G_GNUC_INTERNAL GumModule * _gum_module_make (const gchar * path,
    const GumMemoryRange * range, GumCreateModuleHandleFunc create_handle,
    gpointer create_handle_data, GDestroyNotify create_handle_data_destroy,
    GDestroyNotify destroy_handle);
G_GNUC_INTERNAL GumModule * _gum_module_make_handleless (const gchar * path,
    const GumMemoryRange * range);
G_GNUC_INTERNAL gpointer _gum_module_get_handle (GumModule * self);
G_GNUC_INTERNAL void _gum_module_enumerate_exports (GumModule * self,
    GumFoundExportFunc func, gpointer user_data);

G_END_DECLS

#endif
