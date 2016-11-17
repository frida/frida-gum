/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukbundle.h"

#include "gumdukscript-priv.h"

void
gum_duk_bundle_load (const GumDukRuntimeModule * modules,
                     duk_context * ctx)
{
  const GumDukRuntimeModule * cur;

  for (cur = modules; cur->bytecode != NULL; cur++)
  {
    duk_push_external_buffer (ctx);
    duk_config_buffer (ctx, -1, (void *) cur->bytecode, cur->bytecode_size);
    duk_load_function (ctx);
    if (duk_pcall (ctx, 0) != DUK_EXEC_SUCCESS)
      _gum_duk_panic (ctx, duk_safe_to_string (ctx, -1));
    duk_pop (ctx);
  }
}
