/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptsymbol.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_symbol_throw_not_yet_available)

static const JSStaticFunction gumjs_symbol_functions[] =
{
  { "fromAddress", gumjs_symbol_throw_not_yet_available, GUMJS_RO },
  { "fromName", gumjs_symbol_throw_not_yet_available, GUMJS_RO },
  { "getFunctionByName", gumjs_symbol_throw_not_yet_available, GUMJS_RO },
  { "findFunctionsNamed", gumjs_symbol_throw_not_yet_available, GUMJS_RO },
  { "findFunctionsMatching", gumjs_symbol_throw_not_yet_available,
    GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_script_symbol_init (GumScriptSymbol * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef symbol;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Symbol";
  def.staticFunctions = gumjs_symbol_functions;
  klass = JSClassCreate (&def);
  symbol = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "DebugSymbol", symbol);
}

void
_gum_script_symbol_dispose (GumScriptSymbol * self)
{
  (void) self;
}

void
_gum_script_symbol_finalize (GumScriptSymbol * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "DebugSymbol API not yet available in the JavaScriptCore runtime");
  return NULL;
}
