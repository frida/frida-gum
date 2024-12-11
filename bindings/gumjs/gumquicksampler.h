/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_SAMPLER_H__
#define __GUM_QUICK_SAMPLER_H__

#include "gumquickobject.h"

G_BEGIN_DECLS

typedef struct _GumQuickSampler GumQuickSampler;

struct _GumQuickSampler
{
  GumQuickCore * core;

  JSClassID sampler_class;
  JSClassID wallclock_sampler_class;
  JSClassID user_time_sampler_class;

  GumQuickObjectManager objects;
};

G_GNUC_INTERNAL void _gum_quick_sampler_init (GumQuickSampler * self,
    JSValue ns, GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_sampler_flush (GumQuickSampler * self);
G_GNUC_INTERNAL void _gum_quick_sampler_dispose (GumQuickSampler * self);
G_GNUC_INTERNAL void _gum_quick_sampler_finalize (GumQuickSampler * self);

G_END_DECLS

#endif