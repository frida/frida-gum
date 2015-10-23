/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptthread.h"

#include "gumjscriptmacros.h"

enum _GumBacktracerType
{
  GUM_BACKTRACER_ACCURATE = 1,
  GUM_BACKTRACER_FUZZY = 2
};

GUMJS_DECLARE_FUNCTION (gumjs_thread_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_thread_functions[] =
{
  { "backtrace", gumjs_thread_throw_not_yet_available, gumjs_attrs },
  { "sleep", gumjs_thread_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_thread_init (GumScriptThread * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef thread;
  JSObjectRef backtracer;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Thread";
  def.staticFunctions = gumjs_thread_functions;
  klass = JSClassCreate (&def);
  thread = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Thread", thread);

  backtracer = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_uint (ctx, backtracer, "ACCURATE", GUM_BACKTRACER_ACCURATE);
  _gumjs_object_set_uint (ctx, backtracer, "FUZZY", GUM_BACKTRACER_FUZZY);
  _gumjs_object_set (ctx, scope, "Backtracer", backtracer);
}

void
_gum_script_thread_dispose (GumScriptThread * self)
{
  (void) self;
}

void
_gum_script_thread_finalize (GumScriptThread * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Thread API not yet available in the JavaScriptCore runtime");
  return NULL;
}
