/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptkernel.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_FUNCTION (gumjs_kernel_throw_not_yet_available)

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_kernel_functions[] =
{
  { "enumerateThreads", gumjs_kernel_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_kmemory_functions[] =
{
  { "readByteArray", gumjs_kernel_throw_not_yet_available, gumjs_attrs },
  { "writeByteArray", gumjs_kernel_throw_not_yet_available, gumjs_attrs },
  { "_enumerateRanges", gumjs_kernel_throw_not_yet_available, gumjs_attrs },

  { NULL, NULL, 0 }
};

void
_gum_script_kernel_init (GumScriptKernel * self,
                          GumScriptCore * core,
                          JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef kernel, memory;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Kernel";
  def.staticFunctions = gumjs_kernel_functions;
  klass = JSClassCreate (&def);
  kernel = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Kernel", kernel);

  def = kJSClassDefinitionEmpty;
  def.className = "Memory";
  def.staticFunctions = gumjs_kmemory_functions;
  klass = JSClassCreate (&def);
  memory = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Memory", memory);
}

void
_gum_script_kernel_dispose (GumScriptKernel * self)
{
  (void) self;
}

void
_gum_script_kernel_finalize (GumScriptKernel * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Kernel API not yet available in the JavaScriptCore runtime");
  return NULL;
}
