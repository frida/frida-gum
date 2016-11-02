/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_BUNDLE_H__
#define __GUM_V8_BUNDLE_H__

#include <glib.h>
#include <v8.h>

#define GUM_MAX_SCRIPT_SOURCE_CHUNKS 10

struct GumV8Bundle
{
  GPtrArray * scripts;
  v8::Isolate * isolate;
};

struct GumV8Source
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

G_GNUC_INTERNAL GumV8Bundle * gum_v8_bundle_new (v8::Isolate * isolate,
    const GumV8Source * sources);
G_GNUC_INTERNAL void gum_v8_bundle_free (GumV8Bundle * bundle);

G_GNUC_INTERNAL void gum_v8_bundle_run (GumV8Bundle * self);

#endif
