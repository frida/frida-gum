/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptsocket.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_socket_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_socket_functions[] =
{
  { "xxx", gumjs_socket_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_socket_init (GumScriptSocket * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef socket;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Socket";
  def.staticFunctions = gumjs_socket_functions;
  klass = JSClassCreate (&def);
  socket = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Socket", socket);
}

void
_gum_script_socket_dispose (GumScriptSocket * self)
{
  (void) self;
}

void
_gum_script_socket_finalize (GumScriptSocket * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Socket API not yet available in the JavaScriptCore runtime");
  return NULL;
}
