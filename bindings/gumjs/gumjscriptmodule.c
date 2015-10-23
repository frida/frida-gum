/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptmodule.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_module_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_module_functions[] =
{
  { "enumerateImports", gumjs_module_throw_not_yet_available, gumjs_attrs },
  { "enumerateExports", gumjs_module_throw_not_yet_available, gumjs_attrs },
  { "enumerateRanges", gumjs_module_throw_not_yet_available, gumjs_attrs },
  { "findBaseAddress", gumjs_module_throw_not_yet_available, gumjs_attrs },
  { "findExportByName", gumjs_module_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_module_init (GumScriptModule * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef module;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Module";
  def.staticFunctions = gumjs_module_functions;
  klass = JSClassCreate (&def);
  module = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Module", module);
}

void
_gum_script_module_dispose (GumScriptModule * self)
{
  (void) self;
}

void
_gum_script_module_finalize (GumScriptModule * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Module API not yet available in the JavaScriptCore runtime");
  return NULL;
}
