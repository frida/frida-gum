/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_INSTRUCTION_H__
#define __GUM_DUK_INSTRUCTION_H__

#include "gumdukcore.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumDukInstruction GumDukInstruction;
typedef struct _GumDukInstructionValue GumDukInstructionValue;

struct _GumDukInstruction
{
  GumDukCore * core;

  csh capstone;

  GumDukHeapPtr instruction;
};

struct _GumDukInstructionValue
{
  GumDukHeapPtr object;
  const cs_insn * insn;
  gconstpointer target;

  GumDukInstruction * module;
};

G_GNUC_INTERNAL void _gum_duk_instruction_init (GumDukInstruction * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_instruction_dispose (
    GumDukInstruction * self);
G_GNUC_INTERNAL void _gum_duk_instruction_finalize (
    GumDukInstruction * self);

G_GNUC_INTERNAL GumDukInstructionValue * _gum_duk_push_instruction (
    duk_context * ctx, csh capstone, const cs_insn * insn, gboolean is_owned,
    gconstpointer target, GumDukInstruction * module);

G_GNUC_INTERNAL GumDukInstructionValue * _gum_duk_instruction_new (
    GumDukInstruction * module);
G_GNUC_INTERNAL void _gum_duk_instruction_release (
    GumDukInstructionValue * value);

G_END_DECLS

#endif
