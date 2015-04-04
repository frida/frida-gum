/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_INSTRUCTION_H__
#define __GUM_SCRIPT_INSTRUCTION_H__

#include "gumscriptcore.h"

#include <capstone/capstone.h>
#include <v8.h>

typedef struct _GumScriptInstruction GumScriptInstruction;

struct _GumScriptInstruction
{
  GumScriptCore * core;

  csh capstone;
  GHashTable * instructions;

  GumPersistent<v8::Object>::type * value;
};

G_GNUC_INTERNAL void _gum_script_instruction_init (GumScriptInstruction * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_instruction_realize (
    GumScriptInstruction * self);
G_GNUC_INTERNAL void _gum_script_instruction_dispose (
    GumScriptInstruction * self);
G_GNUC_INTERNAL void _gum_script_instruction_finalize (
    GumScriptInstruction * self);

#endif
