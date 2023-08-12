/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 DaVinci <nstefanclaudel13@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8thread.h"

#include "gumv8macros.h"

#define GUMJS_MODULE_NAME Thread

using namespace v8;

GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

static const GumV8Function gumjs_thread_functions[] =
{
  { "_backtrace", gumjs_thread_backtrace },
  { "sleep", gumjs_thread_sleep },

  { NULL, NULL }
};

void
_gum_v8_thread_init (GumV8Thread * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto thread = _gum_v8_create_module ("Thread", scope, isolate);
  _gum_v8_module_add (module, thread, gumjs_thread_functions, isolate);

  _gum_v8_create_module ("Backtracer", scope, isolate);
}

void
_gum_v8_thread_realize (GumV8Thread * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto backtracer = context->Global ()->Get (context,
      _gum_v8_string_new_ascii (isolate, "Backtracer")).ToLocalChecked ()
      .As<Object> ();

  auto accurate = Symbol::ForApi (isolate,
      _gum_v8_string_new_ascii (isolate, "Backtracer.ACCURATE"));
  backtracer->DefineOwnProperty (context,
      _gum_v8_string_new_ascii (isolate, "ACCURATE"), accurate,
      (PropertyAttribute) (ReadOnly | DontDelete)).ToChecked ();
  self->accurate_enum_value = new Global<Symbol> (isolate, accurate);

  auto fuzzy = Symbol::ForApi (isolate,
      _gum_v8_string_new_ascii (isolate, "Backtracer.FUZZY"));
  backtracer->DefineOwnProperty (context,
      _gum_v8_string_new_ascii (isolate, "FUZZY"), fuzzy,
      (PropertyAttribute) (ReadOnly | DontDelete)).ToChecked ();
  self->fuzzy_enum_value = new Global<Symbol> (isolate, fuzzy);
}

void
_gum_v8_thread_dispose (GumV8Thread * self)
{
  delete self->fuzzy_enum_value;
  self->fuzzy_enum_value = nullptr;

  delete self->accurate_enum_value;
  self->accurate_enum_value = nullptr;
}

void
_gum_v8_thread_finalize (GumV8Thread * self)
{
  g_clear_object (&self->accurate_backtracer);
  g_clear_object (&self->fuzzy_backtracer);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  auto context = isolate->GetCurrentContext ();

  GumCpuContext * cpu_context = NULL;
  Local<Value> raw_type;
  guint limit;
  if (!_gum_v8_args_parse (args, "C?Vu", &cpu_context, &raw_type, &limit))
    return;

  if (!raw_type->IsSymbol ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid backtracer value");
    return;
  }
  Local<Symbol> type = raw_type.As<Symbol> ();
  gboolean accurate = TRUE;
  if (type->StrictEquals (
        Local<Symbol>::New (isolate, *module->fuzzy_enum_value)))
  {
    accurate = FALSE;
  }
  else if (!type->StrictEquals (
        Local<Symbol>::New (isolate, *module->accurate_enum_value)))
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid backtracer enum value");
    return;
  }

  GumBacktracer * backtracer;
  if (accurate)
  {
    if (module->accurate_backtracer == NULL)
      module->accurate_backtracer = gum_backtracer_make_accurate ();
    backtracer = module->accurate_backtracer;
  }
  else
  {
    if (module->fuzzy_backtracer == NULL)
      module->fuzzy_backtracer = gum_backtracer_make_fuzzy ();
    backtracer = module->fuzzy_backtracer;
  }
  if (backtracer == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, accurate
            ? "backtracer not yet available for this platform; "
            "please try Thread.backtrace(context, Backtracer.FUZZY)"
            : "backtracer not yet available for this platform; "
            "please try Thread.backtrace(context, Backtracer.ACCURATE)");
    return;
  }

  GumReturnAddressArray ret_addrs;
  if (limit != 0)
  {
    gum_backtracer_generate_with_limit (backtracer, cpu_context, &ret_addrs,
        limit);
  }
  else
  {
    gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);
  }

  auto result = Array::New (isolate, ret_addrs.len);
  for (guint i = 0; i != ret_addrs.len; i++)
  {
    result->Set (context, i,
        _gum_v8_native_pointer_new (ret_addrs.items[i], core)).Check ();
  }
  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  gdouble delay;

  if (!_gum_v8_args_parse (args, "n", &delay))
    return;

  if (delay < 0)
    return;

  {
    ScriptUnlocker unlocker (core);

    g_usleep (delay * G_USEC_PER_SEC);
  }
}
