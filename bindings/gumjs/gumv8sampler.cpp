/*
 * Copyright (C) 2013-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8sampler.h"
#include "gumsampler.h"
#include "gumwallclocksampler.h"
#include "gumusertimesampler.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#define GUMJS_MODULE_NAME Sampler

using namespace v8;

GUMJS_DECLARE_CONSTRUCTOR (gumjs_sampler_construct)
GUMJS_DECLARE_FUNCTION (gumjs_sampler_sample)
GUMJS_DECLARE_CONSTRUCTOR (gumjs_wallclock_sampler_construct)
GUMJS_DECLARE_CONSTRUCTOR (gumjs_user_time_sampler_construct)

static const GumV8Function gumjs_sampler_functions[] =
{
  { "sample", gumjs_sampler_sample },

  { NULL, NULL }
};

void
_gum_v8_sampler_init (GumV8Sampler * self,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto sampler = _gum_v8_create_class ("Sampler",
      gumjs_sampler_construct, scope, module, isolate);
  _gum_v8_class_add (sampler, gumjs_sampler_functions, module, isolate);
  self->sampler = new Global<FunctionTemplate> (isolate, sampler);

  auto wallclock_sampler = _gum_v8_create_class ("WallClockSampler",
      gumjs_wallclock_sampler_construct, scope, module, isolate);
  wallclock_sampler->Inherit (sampler);

  auto user_time_sampler = _gum_v8_create_class ("UserTimeSampler",
      gumjs_user_time_sampler_construct, scope, module, isolate);
  user_time_sampler->Inherit (sampler);
}

void
_gum_v8_sampler_realize (GumV8Sampler * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_sampler_flush (GumV8Sampler * self)
{
  gum_v8_object_manager_flush (&self->objects);
}

void
_gum_v8_sampler_dispose (GumV8Sampler * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_sampler_finalize (GumV8Sampler * self)
{
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_sampler_construct)
{
  _gum_v8_throw_ascii_literal (isolate, "not user-instantiable");
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_sampler_sample, GumSampler)
{
  GumSample sample;

  sample = gum_sampler_sample (self);

  info.GetReturnValue ().Set (_gum_v8_uint64_new (sample, core));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_wallclock_sampler_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new WallClockSampler()` to create a new instance");
    return;
  }

  auto sampler = gum_wallclock_sampler_new ();

  gum_v8_object_manager_add (&module->objects, wrapper, sampler, module);

  wrapper->SetAlignedPointerInInternalField (0, sampler);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_user_time_sampler_construct)
{
  GumThreadId thread_id = gum_process_get_current_thread_id ();

  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new UserTimeSampler()` to create a new instance");
    return;
  }

  if (!_gum_v8_args_parse (args, "|Z", &thread_id))
    return;

  auto sampler = gum_user_time_sampler_new_with_thread_id (thread_id);

  gum_v8_object_manager_add (&module->objects, wrapper, sampler, module);

  wrapper->SetAlignedPointerInInternalField (0, sampler);
}