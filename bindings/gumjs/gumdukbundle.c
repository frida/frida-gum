/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukbundle.h"

#include "gumdukscript-priv.h"

void
gum_duk_bundle_load (const GumDukSource * sources,
                     duk_context * ctx)
{
  const GumDukSource * cur;

  for (cur = sources; cur->name != NULL; cur++)
  {
    gchar * source, * url;
    int result;

    source = g_strjoinv (NULL, (gchar **) cur->chunks);

    url = g_strconcat ("file:///", cur->name, NULL);

    duk_push_string (ctx, source);
    duk_push_string (ctx, url);

    result = duk_pcompile (ctx, DUK_COMPILE_EVAL);
    if (result != 0)
    {
      duk_get_prop_string (ctx, -1, "stack");
      _gumjs_panic (ctx, duk_safe_to_string (ctx, -1));
      duk_pop (ctx);
    }

    result = duk_pcall (ctx, 0);
    if (result != 0)
    {
      duk_get_prop_string (ctx, -1, "stack");
      _gumjs_panic (ctx, duk_safe_to_string (ctx, -1));
      duk_pop (ctx);
    }

    duk_pop (ctx);

    g_free (url);
    g_free (source);
  }
}
