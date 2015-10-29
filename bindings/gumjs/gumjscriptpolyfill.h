/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_POLYFILL_H__
#define __GUM_JSCRIPT_POLYFILL_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptPolyfill GumScriptPolyfill;

struct _GumScriptPolyfill
{
  GumScriptCore * core;

  gboolean disposed;

  JSClassRef proxy;
};

G_GNUC_INTERNAL void _gum_script_polyfill_init (GumScriptPolyfill * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_polyfill_dispose (GumScriptPolyfill * self);
G_GNUC_INTERNAL void _gum_script_polyfill_finalize (GumScriptPolyfill * self);

G_END_DECLS

#endif
