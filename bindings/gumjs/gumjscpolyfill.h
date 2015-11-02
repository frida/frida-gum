/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_POLYFILL_H__
#define __GUM_JSCRIPT_POLYFILL_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscPolyfill GumJscPolyfill;

struct _GumJscPolyfill
{
  GumJscCore * core;

  JSClassRef proxy;
};

G_GNUC_INTERNAL void _gum_jsc_polyfill_init (GumJscPolyfill * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_polyfill_dispose (GumJscPolyfill * self);
G_GNUC_INTERNAL void _gum_jsc_polyfill_finalize (GumJscPolyfill * self);

G_END_DECLS

#endif
