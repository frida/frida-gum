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

    result = duk_peval (ctx);
    if (result != 0)
    {
      _gumjs_panic (ctx, duk_safe_to_string (ctx, -2));
    }

    duk_pop (ctx);

    g_free (url);
    g_free (source);
  }
}
