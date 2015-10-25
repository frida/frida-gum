/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptstalker.h"

#include "gumjscriptmacros.h"

GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_throw_not_yet_available)

static const JSStaticValue gumjs_stalker_values[] =
{
  {
    "trustThreshold",
    gumjs_stalker_get_trust_threshold,
    gumjs_stalker_set_trust_threshold,
    GUMJS_RW
  },
  {
    "queueCapacity",
    gumjs_stalker_get_queue_capacity,
    gumjs_stalker_set_queue_capacity,
    GUMJS_RW
  },
  {
    "queueDrainInterval",
    gumjs_stalker_get_queue_drain_interval,
    gumjs_stalker_set_queue_drain_interval,
    GUMJS_RW
  },

  { NULL, NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_stalker_functions[] =
{
  { "garbageCollect", gumjs_stalker_throw_not_yet_available, GUMJS_RO },
  { "follow", gumjs_stalker_throw_not_yet_available, GUMJS_RO },
  { "unfollow", gumjs_stalker_throw_not_yet_available, GUMJS_RO },
  { "addCallProbe", gumjs_stalker_throw_not_yet_available, GUMJS_RO },
  { "removeCallProbe", gumjs_stalker_throw_not_yet_available, GUMJS_RO },

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
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  def = kJSClassDefinitionEmpty;
  def.className = "Stalker";
  def.staticValues = gumjs_stalker_values;
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

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  GumStalker * stalker;

  stalker = _gum_script_stalker_get (JSObjectGetPrivate (object));

  return JSValueMakeNumber (ctx, gum_stalker_get_trust_threshold (stalker));
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  GumStalker * stalker;
  gint threshold;

  stalker = _gum_script_stalker_get (JSObjectGetPrivate (object));

  if (!_gumjs_args_parse (args, "i", &threshold))
    return false;

  gum_stalker_set_trust_threshold (stalker, threshold);
  return true;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  GumScriptStalker * self;

  self = JSObjectGetPrivate (object);

  return JSValueMakeNumber (ctx, self->queue_capacity);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  GumScriptStalker * self;
  guint capacity;

  self = JSObjectGetPrivate (object);

  if (!_gumjs_args_parse (args, "u", &capacity))
    return false;

  self->queue_capacity = capacity;
  return true;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  GumScriptStalker * self;

  self = JSObjectGetPrivate (object);

  return JSValueMakeNumber (ctx, self->queue_drain_interval);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  GumScriptStalker * self;
  guint interval;

  self = JSObjectGetPrivate (object);

  if (!_gumjs_args_parse (args, "u", &interval))
    return false;

  self->queue_drain_interval = interval;
  return true;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Stalker API not yet available in the JavaScriptCore runtime");
  return NULL;
}
