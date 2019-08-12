/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_MODULE_H__
#define __GUM_DUK_MODULE_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukModule GumDukModule;

struct _GumDukModule
{
  GumDukCore * core;

  GumDukHeapPtr klass;
};

G_GNUC_INTERNAL void _gum_duk_module_init (GumDukModule * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_module_dispose (GumDukModule * self);
G_GNUC_INTERNAL void _gum_duk_module_finalize (GumDukModule * self);

G_GNUC_INTERNAL void _gum_duk_push_module (duk_context * ctx,
    const GumModuleDetails * details, GumDukModule * module);

G_END_DECLS

#endif
