/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbundle.h"

using namespace v8;

static void gum_script_bundle_script_free (Persistent<UnboundScript> * script);
static void gum_script_bundle_script_run (Persistent<UnboundScript> * script,
    GumScriptBundle * bundle);

GumScriptBundle *
gum_script_bundle_new (Isolate * isolate,
                       const GumScriptSource * sources)
{
  GumScriptBundle * bundle;
  const GumScriptSource * source;

  bundle = g_slice_new (GumScriptBundle);

  bundle->scripts = g_ptr_array_new_with_free_func (
      (GDestroyNotify) gum_script_bundle_script_free);
  bundle->isolate = isolate;

  for (source = sources; source->name != NULL; source++)
  {
    Local<String> resource_name (String::NewFromOneByte (isolate,
        reinterpret_cast<const uint8_t *> (source->name),
        NewStringType::kNormal).ToLocalChecked ());
    ScriptOrigin origin (resource_name);

    gchar * str = g_strjoinv (NULL, (gchar **) source->chunks);
    Local<String> source_string (String::NewFromUtf8 (isolate, str));
    g_free (str);
    ScriptCompiler::Source source (source_string, origin);

    Persistent<UnboundScript> * script = new Persistent<UnboundScript> (
        isolate, ScriptCompiler::CompileUnboundScript (isolate,
        &source).ToLocalChecked ());
    g_ptr_array_add (bundle->scripts, script);
  }

  return bundle;
}

void
gum_script_bundle_free (GumScriptBundle * bundle)
{
  g_ptr_array_unref (bundle->scripts);

  g_slice_free (GumScriptBundle, bundle);
}

void
gum_script_bundle_run (GumScriptBundle * self)
{
  g_ptr_array_foreach (self->scripts, (GFunc) gum_script_bundle_script_run,
      self);
}

static void
gum_script_bundle_script_free (Persistent<UnboundScript> * script)
{
  delete script;
}

static void
gum_script_bundle_script_run (Persistent<UnboundScript> * script,
                              GumScriptBundle * bundle)
{
  Local<UnboundScript> s (Local<UnboundScript>::New (bundle->isolate, *script));
  s->BindToCurrentContext ()->Run ();
}

