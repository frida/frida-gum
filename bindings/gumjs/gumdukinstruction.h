/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_INSTRUCTION_H__
#define __GUM_DUK_INSTRUCTION_H__

#include "gumdukcore.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumDukInstruction GumDukInstruction;

struct _GumDukInstruction
{
  GumDukCore * core;

  csh capstone;

  GumDukHeapPtr instruction;
};

G_GNUC_INTERNAL void _gum_duk_instruction_init (GumDukInstruction * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_instruction_dispose (
    GumDukInstruction * self);
G_GNUC_INTERNAL void _gum_duk_instruction_finalize (
    GumDukInstruction * self);

G_GNUC_INTERNAL void _gum_duk_push_instruction (duk_context * ctx,
    const cs_insn * insn, gconstpointer target, GumDukInstruction * module);

G_END_DECLS

#endif
