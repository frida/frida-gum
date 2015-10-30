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

typedef struct _GumV8Bundle GumV8Bundle;
typedef struct _GumV8Source GumV8Source;

struct _GumV8Bundle
{
  GPtrArray * scripts;
  v8::Isolate * isolate;
};

struct _GumV8Source
{
  const gchar * name;
  const gchar * chunks[GUM_MAX_SCRIPT_SOURCE_CHUNKS];
};

G_BEGIN_DECLS

GumV8Bundle * gum_v8_bundle_new (v8::Isolate * isolate,
    const GumV8Source * sources);
void gum_v8_bundle_free (GumV8Bundle * bundle);

void gum_v8_bundle_run (GumV8Bundle * self);

G_END_DECLS

#endif
