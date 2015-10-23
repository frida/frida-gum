/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptstalker.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_stalker_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_stalker_functions[] =
{
  { "xxx", gumjs_stalker_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_stalker_init (GumScriptStalker * self,
                          GumScriptCore * core,
                          JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef stalker;

  self->core = core;
  self->stalker = NULL;

  def = kJSClassDefinitionEmpty;
  def.className = "Stalker";
  def.staticFunctions = gumjs_stalker_functions;
  klass = JSClassCreate (&def);
  stalker = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Stalker", stalker);
}

void
_gum_script_stalker_flush (GumScriptStalker * self)
{
  if (self->stalker != NULL)
  {
    gum_stalker_stop (self->stalker);
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

void
_gum_script_stalker_dispose (GumScriptStalker * self)
{
  (void) self;
}

void
_gum_script_stalker_finalize (GumScriptStalker * self)
{
  (void) self;
}

GumStalker *
_gum_script_stalker_get (GumScriptStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Stalker API not yet available in the JavaScriptCore runtime");
  return NULL;
}
