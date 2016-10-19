/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukstalker.h"

#include "gumdukmacros.h"

GUMJS_DECLARE_CONSTRUCTOR (gumjs_stalker_construct)
GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_throw_not_yet_available)

static const GumDukPropertyEntry gumjs_stalker_values[] =
{
  {
    "trustThreshold",
    gumjs_stalker_get_trust_threshold,
    gumjs_stalker_set_trust_threshold
  },
  {
    "queueCapacity",
    gumjs_stalker_get_queue_capacity,
    gumjs_stalker_set_queue_capacity
  },
  {
    "queueDrainInterval",
    gumjs_stalker_get_queue_drain_interval,
    gumjs_stalker_set_queue_drain_interval
  },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_stalker_functions[] =
{
  { "garbageCollect", gumjs_stalker_throw_not_yet_available, 0 },
  { "_follow", gumjs_stalker_throw_not_yet_available, 4 },
  { "unfollow", gumjs_stalker_throw_not_yet_available, 1 },
  { "addCallProbe", gumjs_stalker_throw_not_yet_available, 2 },
  { "removeCallProbe", gumjs_stalker_throw_not_yet_available, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_stalker_init (GumDukStalker * self,
                       GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;
  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  _gum_duk_store_module_data (ctx, "stalker", self);

  duk_push_c_function (ctx, gumjs_stalker_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_stalker_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_stalker_values);
  duk_put_global_string (ctx, "Stalker");
}

void
_gum_duk_stalker_flush (GumDukStalker * self)
{
  if (self->stalker != NULL)
  {
    gum_stalker_stop (self->stalker);
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

void
_gum_duk_stalker_dispose (GumDukStalker * self)
{
  (void) self;
}

void
_gum_duk_stalker_finalize (GumDukStalker * self)
{
  (void) self;
}

GumStalker *
_gum_duk_stalker_get (GumDukStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

static GumDukStalker *
gumjs_stalker_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "stalker");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_stalker_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  GumStalker * stalker = _gum_duk_stalker_get (gumjs_stalker_from_args (args));

  duk_push_number (ctx, gum_stalker_get_trust_threshold (stalker));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  GumStalker * stalker;
  gint threshold;

  (void) ctx;

  stalker = _gum_duk_stalker_get (gumjs_stalker_from_args (args));

  _gum_duk_args_parse (args, "i", &threshold);

  gum_stalker_set_trust_threshold (stalker, threshold);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  GumDukStalker * self = gumjs_stalker_from_args (args);

  duk_push_number (ctx, self->queue_capacity);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  GumDukStalker * self = gumjs_stalker_from_args (args);

  (void) ctx;

  _gum_duk_args_parse (args, "u", &self->queue_capacity);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  GumDukStalker * self = gumjs_stalker_from_args (args);

  duk_push_number (ctx, self->queue_drain_interval);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  GumDukStalker * self = gumjs_stalker_from_args (args);

  (void) ctx;

  _gum_duk_args_parse (args, "u", &self->queue_drain_interval);
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_throw_not_yet_available)
{
  (void) args;

  _gum_duk_throw (ctx,
      "Stalker API not yet available in the Duktape runtime");
  return 0;
}
