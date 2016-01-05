/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscpolyfill.h"

#include "gumjscmacros.h"
#include "gumjscscript-priv.h"

#define GUMJS_MODULE_FROM_ARGS(args) \
  (&(args)->core->script->priv->polyfill)
#define GUMJS_PROXY(o) \
  ((GumJscProxy *) JSObjectGetPrivate (o))

typedef struct _GumJscProxy GumJscProxy;

struct _GumJscProxy
{
  JSObjectRef has;
  JSObjectRef get;
  JSObjectRef set;
  JSObjectRef enumerate;
  JSObjectRef target;
  JSObjectRef handler;

  GumJscPolyfill * parent;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_proxy_construct)
GUMJS_DECLARE_FINALIZER (gumjs_proxy_finalize)
static bool gumjs_proxy_has_property (JSContextRef ctx, JSObjectRef object,
    JSStringRef property_name);
static JSValueRef gumjs_proxy_get_property (JSContextRef ctx,
    JSObjectRef object, JSStringRef property_name, JSValueRef * exception);
static bool gumjs_proxy_set_property (JSContextRef ctx, JSObjectRef object,
    JSStringRef property_name, JSValueRef value, JSValueRef * exception);
static void gumjs_proxy_get_property_names (JSContextRef ctx,
    JSObjectRef object, JSPropertyNameAccumulatorRef property_names);

void
_gum_jsc_polyfill_init (GumJscPolyfill * self,
                        GumJscCore * core,
                        JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef constructor;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.attributes = kJSClassAttributeNoAutomaticPrototype;
  def.className = "Proxy";
  def.finalize = gumjs_proxy_finalize;
  def.hasProperty = gumjs_proxy_has_property;
  def.getProperty = gumjs_proxy_get_property;
  def.setProperty = gumjs_proxy_set_property;
  def.getPropertyNames = gumjs_proxy_get_property_names;
  self->proxy = JSClassCreate (&def);

  def = kJSClassDefinitionEmpty;
  def.className = "ProxyConstructor";
  def.callAsConstructor = gumjs_proxy_construct;
  constructor = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, "Proxy",
      JSObjectMake (ctx, constructor, self));
  JSClassRelease (constructor);
}

void
_gum_jsc_polyfill_dispose (GumJscPolyfill * self)
{
  g_clear_pointer (&self->proxy, JSClassRelease);
}

void
_gum_jsc_polyfill_finalize (GumJscPolyfill * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_proxy_construct)
{
  GumJscPolyfill * parent = GUMJS_MODULE_FROM_ARGS (args);
  GumJscProxy p;
  JSObjectRef target;
  JSObjectRef instance;

  if (!_gumjs_args_parse (args, "OF{has?,get?,set?,enumerate?}",
      &target, &p.has, &p.get, &p.set, &p.enumerate))
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
  p.target = target;
  p.handler = (JSObjectRef) args->values[1];
  JSValueProtect (ctx, p.target);
  JSValueProtect (ctx, p.handler);

  instance = JSObjectMake (ctx, parent->proxy, g_slice_dup (GumJscProxy, &p));
  JSObjectSetPrototype (ctx, instance, JSObjectGetPrototype (ctx, target));

  return instance;
}

GUMJS_DEFINE_FINALIZER (gumjs_proxy_finalize)
{
  GumJscProxy * self = GUMJS_PROXY (object);
  GumJscCore * core = self->parent->core;

  _gum_jsc_core_unprotect_later (core, self->has);
  _gum_jsc_core_unprotect_later (core, self->get);
  _gum_jsc_core_unprotect_later (core, self->set);
  _gum_jsc_core_unprotect_later (core, self->enumerate);
  _gum_jsc_core_unprotect_later (core, self->target);
  _gum_jsc_core_unprotect_later (core, self->handler);

  g_slice_free (GumJscProxy, self);
}

static bool
gumjs_proxy_has_property (JSContextRef ctx,
                          JSObjectRef object,
                          JSStringRef property_name)
{
  GumJscProxy * self;
  GumJscCore * core;

  self = GUMJS_PROXY (object);
  if (self->has == NULL)
    return false;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
    JSValueRef * ex = &scope.exception;
    JSValueRef argv[2];
    JSValueRef value;
    bool result = false;

    argv[0] = self->target;
    argv[1] = JSValueMakeString (ctx, property_name);
    value = JSObjectCallAsFunction (ctx, self->has, self->handler,
        G_N_ELEMENTS (argv), argv, ex);
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
      _gum_jsc_scope_flush (&scope);
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
  GumJscProxy * self;
  GumJscCore * core;

  self = GUMJS_PROXY (object);
  if (self->get == NULL)
    return NULL;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
    JSValueRef argv[3];
    JSValueRef result;

    argv[0] = self->target;
    argv[1] = JSValueMakeString (ctx, property_name);
    argv[2] = object;
    result = JSObjectCallAsFunction (ctx, self->get, self->handler,
        G_N_ELEMENTS (argv), argv, &scope.exception);
    _gum_jsc_scope_flush (&scope);

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
  GumJscProxy * self;
  GumJscCore * core;

  self = GUMJS_PROXY (object);
  if (self->set == NULL)
    return false;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
    JSValueRef argv[4];
    JSValueRef result;

    argv[0] = self->target;
    argv[1] = JSValueMakeString (ctx, property_name);
    argv[2] = value;
    argv[3] = object;
    result = JSObjectCallAsFunction (ctx, self->set, self->handler,
        G_N_ELEMENTS (argv), argv, &scope.exception);
    _gum_jsc_scope_flush (&scope);

    return true;
  }
}

static void
gumjs_proxy_get_property_names (JSContextRef ctx,
                                JSObjectRef object,
                                JSPropertyNameAccumulatorRef property_names)
{
  GumJscProxy * self;
  GumJscCore * core;

  self = GUMJS_PROXY (object);
  if (self->enumerate == NULL)
    return;

  core = JSObjectGetPrivate (JSContextGetGlobalObject (ctx));

  {
    GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
    JSValueRef * ex = &scope.exception;
    JSValueRef value;
    JSObjectRef names;
    guint length, i;

    value = JSObjectCallAsFunction (ctx, self->enumerate, self->handler,
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
      _gum_jsc_scope_flush (&scope);
    }
  }
}
