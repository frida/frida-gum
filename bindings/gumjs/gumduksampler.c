/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksampler.h"

#include "gumdukmacros.h"

#include <gum/gum-prof.h>

GUMJS_DECLARE_CONSTRUCTOR (gumjs_sampler_construct)
GUMJS_DECLARE_FUNCTION (gumjs_sampler_sample)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_wall_clock_sampler_construct)

static const duk_function_list_entry gumjs_sampler_functions[] =
{
  { "sample", gumjs_sampler_sample, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_sampler_init (GumDukSampler * self,
                       GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "sampler", self);

  duk_push_c_function (ctx, gumjs_sampler_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_sampler_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->sampler = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "Sampler");

  _gum_duk_create_subclass (ctx, "Sampler", "WallClockSampler",
      gumjs_wall_clock_sampler_construct, 0, NULL);

  _gum_duk_object_manager_init (&self->objects, self, core);
}

void
_gum_duk_sampler_flush (GumDukSampler * self)
{
  _gum_duk_object_manager_flush (&self->objects);
}

void
_gum_duk_sampler_dispose (GumDukSampler * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_object_manager_free (&self->objects);

  _gum_duk_release_heapptr (scope.ctx, self->sampler);
}

void
_gum_duk_sampler_finalize (GumDukSampler * self)
{
  (void) self;
}

static GumDukSampler *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "sampler");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_sampler_construct)
{
  GumSampler * sampler;
  GumDukSampler * module;

  sampler = GUM_SAMPLER (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  _gum_duk_object_manager_add (&module->objects, ctx, -1, sampler);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_sampler_sample)
{
  GumDukObject * self;

  self = _gum_duk_object_get (args);

  _gum_duk_push_uint64 (ctx, gum_sampler_sample (self->handle), self->core);
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_wall_clock_sampler_construct)
{
  GumDukSampler * module;

  if (!duk_is_constructor_call (ctx))
  {
    _gum_duk_throw (ctx, "use `new WallClockSampler()` to create a new "
        "instance");
  }

  module = gumjs_module_from_args (args);

  duk_push_heapptr (ctx, module->sampler);
  duk_push_this (ctx);
  duk_push_pointer (ctx, gum_wallclock_sampler_new ());
  duk_call_method (ctx, 1);

  return 0;
}
