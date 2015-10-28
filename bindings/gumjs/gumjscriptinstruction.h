/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_INSTRUCTION_H__
#define __GUM_JSCRIPT_INSTRUCTION_H__

#include "gumjscriptcore.h"

#include <capstone/capstone.h>

G_BEGIN_DECLS

typedef struct _GumScriptInstruction GumScriptInstruction;

struct _GumScriptInstruction
{
  GumScriptCore * core;

  csh capstone;

  JSClassRef instruction;
};

G_GNUC_INTERNAL void _gum_script_instruction_init (GumScriptInstruction * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_instruction_dispose (
    GumScriptInstruction * self);
G_GNUC_INTERNAL void _gum_script_instruction_finalize (
    GumScriptInstruction * self);

G_END_DECLS

#endif
