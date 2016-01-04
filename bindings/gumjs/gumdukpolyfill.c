/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukpolyfill.h"

#include "gumdukmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_proxy_create)

static const duk_function_list_entry gumjs_proxy_module_functions[] =
{
  { "create", gumjs_proxy_create, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_polyfill_init (GumDukPolyfill * self,
                        GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_get_global_string (ctx, "Proxy");
  // [ Proxy ]
  duk_put_function_list (ctx, -1, gumjs_proxy_module_functions);
  duk_pop (ctx);
  // []
}

GUMJS_DEFINE_FUNCTION (gumjs_proxy_create)
{
  duk_get_global_string (ctx, "Proxy");
  // [ Proxy ]
  duk_push_object (ctx);
  // [ Proxy target ]
  duk_dup (ctx, 0);
  // [ Proxy target handler ]
  duk_new (ctx, 2);
  // [ instance ]
  return 1;
}

void
_gum_duk_polyfill_dispose (GumDukPolyfill * self)
{
  (void) self;
}

void
_gum_duk_polyfill_finalize (GumDukPolyfill * self)
{
  (void) self;
}
