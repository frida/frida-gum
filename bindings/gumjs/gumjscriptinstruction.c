/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptinstruction.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_instruction_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_instruction_functions[] =
{
  { "_parse", gumjs_instruction_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_instruction_init (GumScriptInstruction * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef instruction;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Instruction";
  def.staticFunctions = gumjs_instruction_functions;
  klass = JSClassCreate (&def);
  instruction = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Instruction", instruction);
}

void
_gum_script_instruction_dispose (GumScriptInstruction * self)
{
  (void) self;
}

void
_gum_script_instruction_finalize (GumScriptInstruction * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Instruction API not yet available in the JavaScriptCore runtime");
  return NULL;
}
