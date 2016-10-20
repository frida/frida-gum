/*
 * Copyright (C) 2014-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_INSTRUCTION_H__
#define __GUM_V8_INSTRUCTION_H__

#include "gumv8core.h"

#include <capstone.h>

struct GumV8Instruction
{
  GumV8Core * core;

  csh capstone;
  GHashTable * instructions;

  GumPersistent<v8::FunctionTemplate>::type * constructor;
  GumPersistent<v8::Object>::type * template_object;
};

G_GNUC_INTERNAL void _gum_v8_instruction_init (GumV8Instruction * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_instruction_realize (
    GumV8Instruction * self);
G_GNUC_INTERNAL void _gum_v8_instruction_dispose (
    GumV8Instruction * self);
G_GNUC_INTERNAL void _gum_v8_instruction_finalize (
    GumV8Instruction * self);

#endif
