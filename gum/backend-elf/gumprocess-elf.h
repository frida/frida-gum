/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PROCESS_ELF_H__
#define __GUM_PROCESS_ELF_H__

#include "gumelfmodule.h"
#include "gummodule.h"
#include "gumprocess.h"

G_BEGIN_DECLS

struct _GumModule
{
#ifndef GUM_DIET
  GObject parent;
#else
  GumObject parent;
#endif

  gpointer handle;
  const gchar * name;
  const gchar * path;
  GumAddress base_address;
  GumElfModule * elf_module;
};

G_GNUC_INTERNAL void _gum_module_enumerate_exports (GumModule * self,
    GumFoundExportFunc func, gpointer user_data);

G_GNUC_INTERNAL gboolean _gum_process_resolve_module_name (const gchar * name,
    gchar ** path, GumAddress * base);

G_END_DECLS

#endif
