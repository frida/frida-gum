/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_THREAD_H__
#define __GUM_JSCRIPT_THREAD_H__

#include "gumjsccore.h"

#include <gum/gumbacktracer.h>

G_BEGIN_DECLS

typedef struct _GumJscThread GumJscThread;

struct _GumJscThread
{
  GumJscCore * core;

  GumBacktracer * accurate_backtracer;
  GumBacktracer * fuzzy_backtracer;
};

G_GNUC_INTERNAL void _gum_jsc_thread_init (GumJscThread * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_thread_dispose (GumJscThread * self);
G_GNUC_INTERNAL void _gum_jsc_thread_finalize (GumJscThread * self);

G_END_DECLS

#endif
