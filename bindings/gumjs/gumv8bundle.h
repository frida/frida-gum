/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_BUNDLE_H__
#define __GUM_V8_BUNDLE_H__

#include <glib.h>
#include <v8.h>

struct GumV8Bundle
{
  GPtrArray * scripts;
  v8::Isolate * isolate;
};

struct GumV8RuntimeModule
{
  const gchar * name;
  const gchar * source_code;
  const gchar * source_map;
};

G_GNUC_INTERNAL GumV8Bundle * gum_v8_bundle_new (v8::Isolate * isolate,
    const GumV8RuntimeModule * modules);
G_GNUC_INTERNAL void gum_v8_bundle_free (GumV8Bundle * bundle);

G_GNUC_INTERNAL void gum_v8_bundle_run (GumV8Bundle * self);

#endif
