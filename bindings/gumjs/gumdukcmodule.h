/*
 * Copyright (C) 2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_CMODULE_H__
#define __GUM_DUK_CMODULE_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukCModule GumDukCModule;

struct _GumDukCModule
{
  GumDukCore * core;

  GHashTable * cmodules;
};

G_GNUC_INTERNAL void _gum_duk_cmodule_init (GumDukCModule * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_cmodule_dispose (GumDukCModule * self);
G_GNUC_INTERNAL void _gum_duk_cmodule_finalize (GumDukCModule * self);

G_END_DECLS

#endif
