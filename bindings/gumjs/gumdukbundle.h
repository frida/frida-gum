/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_BUNDLE_H__
#define __GUM_DUK_BUNDLE_H__

#include "duktape.h"

#include <glib.h>

typedef struct _GumDukRuntimeModule GumDukRuntimeModule;

struct _GumDukRuntimeModule
{
  gconstpointer bytecode;
  gsize bytecode_size;
  const gchar * source_map;
};

G_GNUC_INTERNAL void gum_duk_bundle_load (const GumDukRuntimeModule * modules,
    duk_context * ctx);

#endif
