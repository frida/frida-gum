/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_BUNDLE_H__
#define __GUM_JSCRIPT_BUNDLE_H__

#include <glib.h>
#include <JavaScriptCore/JavaScriptCore.h>

#define GUM_MAX_SCRIPT_SOURCE_CHUNKS 6

typedef struct _GumJscSource GumJscSource;

struct _GumJscSource
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

G_GNUC_INTERNAL void gum_jsc_bundle_load (const GumJscSource * sources,
    JSContextRef ctx);

#endif
