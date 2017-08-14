/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcodewriter.h"

#include "gumdukmacros.h"

static GumDukCodeWriter * gumjs_module_from_args (const GumDukArgs * args);

#include "gumdukcodewriter.inc"

void
_gum_duk_code_writer_init (GumDukCodeWriter * self,
                           GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "code-writer", self);

#include "gumdukcodewriter-init.inc"
}

void
_gum_duk_code_writer_dispose (GumDukCodeWriter * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

#include "gumdukcodewriter-dispose.inc"
}

void
_gum_duk_code_writer_finalize (GumDukCodeWriter * self)
{
}

static GumDukCodeWriter *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "code-writer");
}
