/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptfile.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_file_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_file_functions[] =
{
  { "xxx", gumjs_file_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_file_init (GumScriptFile * self,
                       GumScriptCore * core,
                       JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef file;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "File";
  def.staticFunctions = gumjs_file_functions;
  klass = JSClassCreate (&def);
  file = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "File", file);
}

void
_gum_script_file_dispose (GumScriptFile * self)
{
  (void) self;
}

void
_gum_script_file_finalize (GumScriptFile * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "File API not yet available in the JavaScriptCore runtime");
  return NULL;
}
