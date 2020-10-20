/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickbundle.h"

#include "gumquickscript-priv.h"

void
gum_quick_bundle_load (const GumQuickRuntimeModule * modules,
                       JSContext * ctx)
{
  const GumQuickRuntimeModule * cur;

  for (cur = modules; cur->bytecode != NULL; cur++)
  {
    JSValue code, result;

    code = JS_ReadObject (ctx, cur->bytecode, cur->bytecode_size,
        JS_READ_OBJ_BYTECODE);
    if (JS_IsException (code))
      _gum_quick_panic (ctx, "Runtime bundle could not be parsed");

    result = JS_EvalFunction (ctx, code);
    if (JS_IsException (result))
      _gum_quick_panic (ctx, "Runtime bundle could not be loaded");

    JS_FreeValue (ctx, result);
  }
}
