/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_BUNDLE_H__
#define __GUM_DUK_BUNDLE_H__

#include <glib.h>

#define GUM_MAX_SCRIPT_SOURCE_CHUNKS 6

typedef struct _GumDukSource GumDukSource;

struct _GumDukSource
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

G_GNUC_INTERNAL void gum_duk_bundle_load (const GumDukSource * sources,
    duk_context * ctx);

#endif
