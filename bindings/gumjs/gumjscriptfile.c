/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptfile.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FUNCTION (gumjs_file_throw_not_yet_available)

static const JSStaticFunction gumjs_file_functions[] =
{
  { "write", gumjs_file_throw_not_yet_available, GUMJS_RO },
  { "flush", gumjs_file_throw_not_yet_available, GUMJS_RO },
  { "close", gumjs_file_throw_not_yet_available, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_script_file_init (GumScriptFile * self,
                       GumScriptCore * core,
                       JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "File";
  def.staticFunctions = gumjs_file_functions;
  self->file = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, def.className, JSObjectMakeConstructor (ctx,
      self->file, gumjs_file_construct));
}

void
_gum_script_file_dispose (GumScriptFile * self)
{
  JSClassRelease (self->file);
  self->file = NULL;
}

void
_gum_script_file_finalize (GumScriptFile * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  _gumjs_throw (ctx, exception,
      "File API not yet available in the JavaScriptCore runtime");
  return NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "File API not yet available in the JavaScriptCore runtime");
  return NULL;
}
