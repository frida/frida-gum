/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_BUNDLE_H__
#define __GUM_QUICK_BUNDLE_H__

#include <glib.h>
#include <quickjs.h>

typedef struct _GumQuickRuntimeModule GumQuickRuntimeModule;

struct _GumQuickRuntimeModule
{
  gconstpointer bytecode;
  gsize bytecode_size;
  const gchar * source_map;
};

G_GNUC_INTERNAL void gum_quick_bundle_load (
    const GumQuickRuntimeModule * modules, JSContext * ctx);

#endif
