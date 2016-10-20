/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_API_RESOLVER_H__
#define __GUM_DUK_API_RESOLVER_H__

#include "gumdukobject.h"

G_BEGIN_DECLS

typedef struct _GumDukApiResolver GumDukApiResolver;

struct _GumDukApiResolver
{
  GumDukCore * core;

  GumDukObjectManager objects;

  GumDukHeapPtr api_resolver;
};

G_GNUC_INTERNAL void _gum_duk_api_resolver_init (GumDukApiResolver * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_api_resolver_dispose (GumDukApiResolver * self);
G_GNUC_INTERNAL void _gum_duk_api_resolver_finalize (GumDukApiResolver * self);

G_END_DECLS

#endif
