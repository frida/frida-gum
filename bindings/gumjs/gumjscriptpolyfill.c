/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptpolyfill.h"

#include "gumjscriptmacros.h"

#define GUMJS_PROXY(o) \
  ((GumScriptProxy *) JSObjectGetPrivate (o))

typedef struct _GumScriptProxy GumScriptProxy;

struct _GumScriptProxy
{
  JSObjectRef has;
  JSObjectRef get;
  JSObjectRef set;
  JSObjectRef enumerate;
  JSObjectRef receiver;

  GumScriptPolyfill * parent;
};

GUMJS_DECLARE_FUNCTION (gumjs_proxy_create)
GUMJS_DECLARE_FINALIZER (gumjs_proxy_finalize)
static bool gumjs_proxy_has_property (JSContextRef ctx, JSObjectRef object,
    JSStringRef property_name);
static JSValueRef gumjs_proxy_get_property (JSContextRef ctx,
    JSObjectRef object, JSStringRef property_name, JSValueRef * exception);
static bool gumjs_proxy_set_property (JSContextRef ctx, JSObjectRef object,
    JSStringRef property_name, JSValueRef value, JSValueRef * exception);
static void gumjs_proxy_get_property_names (JSContextRef ctx,
    JSObjectRef object, JSPropertyNameAccumulatorRef property_names);

static const JSStaticFunction gumjs_proxy_module_functions[] =
{
  { "create", gumjs_proxy_create, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_script_polyfill_init (GumScriptPolyfill * self,
                       GumScriptCore * core,
                       JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef module;

  self->core = core;

  self->disposed = FALSE;

  def = kJSClassDefinitionEmpty;
  def.className = "ProxyModule";
  def.staticFunctions = gumjs_proxy_module_functions;
  klass = JSClassCreate (&def);
  module = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Proxy", module);

  def = kJSClassDefinitionEmpty;
  def.className = "Proxy";
  def.finalize = gumjs_proxy_finalize;
  def.hasProperty = gumjs_proxy_has_property;
  def.getProperty = gumjs_proxy_get_property;
  def.setProperty = gumjs_proxy_set_property;
  def.getPropertyNames = gumjs_proxy_get_property_names;
  self->proxy = JSClassCreate (&def);
}

void
_gum_script_polyfill_dispose (GumScriptPolyfill * self)
{
  g_clear_pointer (&self->proxy, JSClassRelease);

  self->disposed = TRUE;
}

void
_gum_script_polyfill_finalize (GumScriptPolyfill * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_proxy_create)
{
  GumScriptPolyfill * parent;
  GumScriptProxy p;

  parent = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "F{has?,get?,set?,enumerate?}",
      &p.has, &p.get, &p.set, &p.enumerate))
    return NULL;
  p.parent = parent;

  if (p.has != NULL)
    JSValueProtect (ctx, p.has);
  if (p.get != NULL)
    JSValueProtect (ctx, p.get);
  if (p.set != NULL)
    JSValueProtect (ctx, p.set);
  if (p.enumerate != NULL)
    JSValueProtect (ctx, p.enumerate);
  p.receiver = (JSObjectRef) args->values[0];
  JSValueProtect (ctx, p.receiver);

  return JSObjectMake (ctx, parent->proxy, g_slice_dup (GumScriptProxy, &p));
}

GUMJS_DEFINE_FINALIZER (gumjs_proxy_finalize)
{
  GumScriptProxy * self = GUMJS_PROXY (object);
  GumScriptPolyfill * parent = self->parent;

  if (!parent->disposed)
  {
    JSContextRef ctx = parent->core->ctx;

    if (self->has != NULL)
      JSValueUnprotect (ctx, self->has);
    if (self->get != NULL)
      JSValueUnprotect (ctx, self->get);
    if (self->set != NULL)
      JSValueUnprotect (ctx, self->set);
    if (self->enumerate != NULL)
      JSValueUnprotect (ctx, self->enumerate);
    JSValueUnprotect (ctx, self->receiver);
  }

  g_slice_free (GumScriptProxy, self);
}

static bool
gumjs_proxy_has_property (JSContextRef ctx,
                          JSObjectRef object,
                          JSStringRef property_name)
{
  GumScriptProxy * self;
  GumScriptCore * core;

  self = GUMJS_PROXY (object);
  if (self->has == NULL)
    return false;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
    JSValueRef * ex = &scope.exception;
    JSValueRef property_name_value, value;
    bool result = false;

    property_name_value = JSValueMakeString (ctx, property_name);
    value = JSObjectCallAsFunction (ctx, self->has, self->receiver,
        1, &property_name_value, ex);
    if (value == NULL)
      goto beach;

    if (!JSValueIsBoolean (ctx, value))
      goto invalid_result_type;

    result = JSValueToBoolean (ctx, value);

    goto beach;

invalid_result_type:
    {
      _gumjs_throw (ctx, ex, "expected has() to return a boolean");
      goto beach;
    }
beach:
    {
      _gum_script_scope_flush (&scope);
      return result;
    }
  }
}

static JSValueRef
gumjs_proxy_get_property (JSContextRef ctx,
                          JSObjectRef object,
                          JSStringRef property_name,
                          JSValueRef * exception)
{
  GumScriptProxy * self;
  GumScriptCore * core;

  self = GUMJS_PROXY (object);
  if (self->get == NULL)
    return NULL;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
    JSValueRef argv[2];
    JSValueRef result;

    argv[0] = object;
    argv[1] = JSValueMakeString (ctx, property_name);
    result = JSObjectCallAsFunction (ctx, self->get, self->receiver,
        G_N_ELEMENTS (argv), argv, &scope.exception);
    _gum_script_scope_flush (&scope);

    return result;
  }
}

static bool
gumjs_proxy_set_property (JSContextRef ctx,
                          JSObjectRef object,
                          JSStringRef property_name,
                          JSValueRef value,
                          JSValueRef * exception)
{
  GumScriptProxy * self;
  GumScriptCore * core;

  self = GUMJS_PROXY (object);
  if (self->set == NULL)
    return false;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
    JSValueRef argv[3];
    JSValueRef result;

    argv[0] = object;
    argv[1] = JSValueMakeString (ctx, property_name);
    argv[2] = value;
    result = JSObjectCallAsFunction (ctx, self->set, self->receiver,
        G_N_ELEMENTS (argv), argv, &scope.exception);
    _gum_script_scope_flush (&scope);

    return true;
  }
}

static void
gumjs_proxy_get_property_names (JSContextRef ctx,
                                JSObjectRef object,
                                JSPropertyNameAccumulatorRef property_names)
{
  GumScriptProxy * self;
  GumScriptCore * core;

  self = GUMJS_PROXY (object);
  if (self->enumerate == NULL)
    return;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
    JSValueRef * ex = &scope.exception;
    JSValueRef value;
    JSObjectRef names;
    guint length, i;

    value = JSObjectCallAsFunction (ctx, self->enumerate, self->receiver,
        0, NULL, ex);
    if (value == NULL)
      goto beach;

    if (!JSValueIsArray (ctx, value))
      goto invalid_result_type;

    names = (JSObjectRef) value;

    if (!_gumjs_object_try_get_uint (ctx, names, "length", &length, ex))
      goto beach;

    for (i = 0; i != length; i++)
    {
      JSValueRef element;
      JSStringRef s;

      element = JSObjectGetPropertyAtIndex (ctx, names, i, ex);
      if (element == NULL)
        goto beach;

      if (!JSValueIsString (ctx, element))
        goto invalid_element_type;

      s = JSValueToStringCopy (ctx, element, ex);
      if (s == NULL)
        goto beach;
      JSPropertyNameAccumulatorAddName (property_names, s);
      JSStringRelease (s);
    }

    goto beach;

invalid_result_type:
    {
      _gumjs_throw (ctx, ex, "expected enumerate() to return an array");
      goto beach;
    }
invalid_element_type:
    {
      _gumjs_throw (ctx, ex, "expected a string");
      goto beach;
    }
beach:
    {
      _gum_script_scope_flush (&scope);
    }
  }
}
