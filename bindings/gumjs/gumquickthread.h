/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_THREAD_H__
#define __GUM_QUICK_THREAD_H__

#include "gumquickcore.h"

#include <gum/gumbacktracer.h>

G_BEGIN_DECLS

typedef struct _GumQuickThread GumQuickThread;

struct _GumQuickThread
{
  GumQuickCore * core;

  GumBacktracer * accurate_backtracer;
  GumBacktracer * fuzzy_backtracer;
};

G_GNUC_INTERNAL void _gum_quick_thread_init (GumQuickThread * self,
    JSValue ns, GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_thread_dispose (GumQuickThread * self);
G_GNUC_INTERNAL void _gum_quick_thread_finalize (GumQuickThread * self);

G_END_DECLS

#endif
