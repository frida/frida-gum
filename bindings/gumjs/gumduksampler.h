/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SAMPLER_H__
#define __GUM_DUK_SAMPLER_H__

#include "gumdukobject.h"

G_BEGIN_DECLS

typedef struct _GumDukSampler GumDukSampler;

struct _GumDukSampler
{
  GumDukCore * core;

  GumDukObjectManager objects;

  GumDukHeapPtr sampler;
};

G_GNUC_INTERNAL void _gum_duk_sampler_init (GumDukSampler * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_sampler_flush (GumDukSampler * self);
G_GNUC_INTERNAL void _gum_duk_sampler_dispose (GumDukSampler * self);
G_GNUC_INTERNAL void _gum_duk_sampler_finalize (GumDukSampler * self);

G_END_DECLS

#endif
