/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_THREAD_H__
#define __GUM_DUK_THREAD_H__

#include "gumdukcore.h"

#include <gum/gumbacktracer.h>

G_BEGIN_DECLS

typedef struct _GumDukThread GumDukThread;

struct _GumDukThread
{
  GumDukCore * core;

  GumBacktracer * accurate_backtracer;
  GumBacktracer * fuzzy_backtracer;
};

G_GNUC_INTERNAL void _gum_duk_thread_init (GumDukThread * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_thread_dispose (GumDukThread * self);
G_GNUC_INTERNAL void _gum_duk_thread_finalize (GumDukThread * self);

G_END_DECLS

#endif
