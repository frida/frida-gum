/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_BUNDLE_H__
#define __GUM_SCRIPT_BUNDLE_H__

#include <glib.h>
#include <v8.h>

#define GUM_MAX_SCRIPT_SOURCE_CHUNKS 6

typedef struct _GumScriptBundle GumScriptBundle;
typedef struct _GumScriptSource GumScriptSource;

struct _GumScriptBundle
{
  GPtrArray * scripts;
  v8::Isolate * isolate;
};

struct _GumScriptSource
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

G_BEGIN_DECLS

GumScriptBundle * gum_script_bundle_new (v8::Isolate * isolate,
    const GumScriptSource * sources);
void gum_script_bundle_free (GumScriptBundle * bundle);

void gum_script_bundle_run (GumScriptBundle * self);

G_END_DECLS

#endif
