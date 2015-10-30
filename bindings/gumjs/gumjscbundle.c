/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscbundle.h"

#include "gumjsc-priv.h"
#include "gumjsccore.h"

void
gum_jsc_bundle_load (const GumJscSource * sources,
                     JSContextRef ctx)
{
  JSObjectRef global;
  const GumJscSource * cur;

  global = JSContextGetGlobalObject (ctx);

  for (cur = sources; cur->name != NULL; cur++)
  {
    JSStringRef source, url;
    gchar * str;
    JSValueRef result, exception;

    str = g_strjoinv (NULL, (gchar **) cur->chunks);
    source = JSStringCreateWithUTF8CString (str);
    g_free (str);

    str = g_strconcat ("file:///", cur->name, NULL);
    url = JSStringCreateWithUTF8CString (str);
    g_free (str);

    result = JSEvaluateScript (ctx, source, global, url, 1, &exception);
    if (result == NULL)
      _gumjs_panic (ctx, exception);

    JSStringRelease (url);
    JSStringRelease (source);
  }
}
