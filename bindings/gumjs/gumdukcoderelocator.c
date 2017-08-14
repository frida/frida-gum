/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcoderelocator.h"

#include "gumdukmacros.h"

static GumDukCodeRelocator * gumjs_module_from_args (const GumDukArgs * args);

#include "gumdukcoderelocator.inc"

void
_gum_duk_code_relocator_init (GumDukCodeRelocator * self,
                              GumDukCodeWriter * writer,
                              GumDukInstruction * instruction,
                              GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  _gum_duk_store_module_data (ctx, "code-relocator", self);

#include "gumdukcoderelocator-init.inc"
}

void
_gum_duk_code_relocator_dispose (GumDukCodeRelocator * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

#include "gumdukcoderelocator-dispose.inc"
}

void
_gum_duk_code_relocator_finalize (GumDukCodeRelocator * self)
{
}

static GumDukCodeRelocator *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "code-relocator");
}
