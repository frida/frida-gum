/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_INSTRUCTION_H__
#define __GUM_JSCRIPT_INSTRUCTION_H__

#include "gumjsccore.h"

#include <capstone/capstone.h>

G_BEGIN_DECLS

typedef struct _GumJscInstruction GumJscInstruction;

struct _GumJscInstruction
{
  GumJscCore * core;

  csh capstone;

  JSClassRef instruction;
};

G_GNUC_INTERNAL void _gum_jsc_instruction_init (GumJscInstruction * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_instruction_dispose (
    GumJscInstruction * self);
G_GNUC_INTERNAL void _gum_jsc_instruction_finalize (
    GumJscInstruction * self);

G_END_DECLS

#endif
