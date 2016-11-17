/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8bundle.h"

#include "gumv8value.h"

using namespace v8;

static void gum_v8_bundle_script_free (Persistent<UnboundScript> * script);
static void gum_v8_bundle_script_run (Persistent<UnboundScript> * script,
    GumV8Bundle * bundle);

GumV8Bundle *
gum_v8_bundle_new (Isolate * isolate,
                   const GumV8RuntimeModule * modules)
{
  auto bundle = g_slice_new (GumV8Bundle);

  bundle->scripts = g_ptr_array_new_with_free_func (
      (GDestroyNotify) gum_v8_bundle_script_free);
  bundle->isolate = isolate;

  for (auto module = modules; module->name != NULL; module++)
  {
    auto resource_name = _gum_v8_string_new_ascii (isolate, module->name);
    ScriptOrigin origin (resource_name);

    auto source_string = String::NewFromUtf8 (isolate, module->source_code);
    ScriptCompiler::Source source_value (source_string, origin);

    auto script = ScriptCompiler::CompileUnboundScript (isolate, &source_value)
        .ToLocalChecked ();

    g_ptr_array_add (bundle->scripts,
        new Persistent<UnboundScript> (isolate, script));
  }

  return bundle;
}

void
gum_v8_bundle_free (GumV8Bundle * bundle)
{
  g_ptr_array_unref (bundle->scripts);

  g_slice_free (GumV8Bundle, bundle);
}

void
gum_v8_bundle_run (GumV8Bundle * self)
{
  g_ptr_array_foreach (self->scripts, (GFunc) gum_v8_bundle_script_run, self);
}

static void
gum_v8_bundle_script_free (Persistent<UnboundScript> * script)
{
  delete script;
}

static void
gum_v8_bundle_script_run (Persistent<UnboundScript> * script,
                          GumV8Bundle * bundle)
{
  auto s = Local<UnboundScript>::New (bundle->isolate, *script);
  s->BindToCurrentContext ()->Run ();
}
