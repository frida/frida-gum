/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptbundle.h"

#include "gumjscriptcore.h"

void
gum_script_bundle_load (const GumScriptSource * sources,
                        JSContextRef ctx)
{
  JSObjectRef global;
  const GumScriptSource * cur;

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
      _gum_script_panic (exception, ctx);

    JSStringRelease (url);
    JSStringRelease (source);
  }
}
