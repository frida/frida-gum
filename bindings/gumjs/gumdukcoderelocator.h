/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_CODE_RELOCATOR_H__
#define __GUM_DUK_CODE_RELOCATOR_H__

#include "gumdukcodewriter.h"
#include "gumdukinstruction.h"

G_BEGIN_DECLS

typedef struct _GumDukCodeRelocator GumDukCodeRelocator;

struct _GumDukCodeRelocator
{
  GumDukCodeWriter * writer;
  GumDukInstruction * instruction;
  GumDukCore * core;

#include "gumdukcoderelocator-fields.inc"
};

G_GNUC_INTERNAL void _gum_duk_code_relocator_init (GumDukCodeRelocator * self,
    GumDukCodeWriter * writer, GumDukInstruction * instruction,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_code_relocator_dispose (
    GumDukCodeRelocator * self);
G_GNUC_INTERNAL void _gum_duk_code_relocator_finalize (
    GumDukCodeRelocator * self);

#include "gumdukcoderelocator-methods.inc"

G_END_DECLS

#endif
