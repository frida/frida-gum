/*
 * Copyright (C) 2016-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8apiresolver.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"

#include <string.h>

#define GUMJS_MODULE_NAME ApiResolver

using namespace v8;

GUMJS_DECLARE_CONSTRUCTOR (gumjs_api_resolver_construct);
GUMJS_DECLARE_FUNCTION (gumjs_api_resolver_enumerate_matches)
static gboolean gum_emit_match (const GumApiDetails * details,
    GumV8MatchContext<GumV8ApiResolver> * mc);

static const GumV8Function gumjs_api_resolver_functions[] =
{
  { "_enumerateMatches", gumjs_api_resolver_enumerate_matches },

  { NULL, NULL }
};

void
_gum_v8_api_resolver_init (GumV8ApiResolver * self,
                           GumV8Core * core,
                           Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto resolver = _gum_v8_create_class ("ApiResolver",
      gumjs_api_resolver_construct, scope, module, isolate);
  _gum_v8_class_add (resolver, gumjs_api_resolver_functions, module, isolate);
}

void
_gum_v8_api_resolver_realize (GumV8ApiResolver * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_api_resolver_dispose (GumV8ApiResolver * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_api_resolver_finalize (GumV8ApiResolver * self)
{
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_api_resolver_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new ApiResolver()` to create a new instance");
    return;
  }

  gchar * type;
  if (!_gum_v8_args_parse (args, "s", &type))
    return;

  GumApiResolver * resolver;
  {
    ScriptUnlocker unlocker (core);

    resolver = gum_api_resolver_make (type);
  }

  g_free (type);

  if (resolver == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "The specified ApiResolver is not available");
    return;
  }

  gum_v8_object_manager_add (&module->objects, wrapper, resolver, module);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_api_resolver_enumerate_matches,
                           GumV8ApiResolverObject)
{
  gchar * query;
  GumV8MatchContext<GumV8ApiResolver> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &query, &mc.on_match,
      &mc.on_complete))
    return;

  GError * error = NULL;
  gum_api_resolver_enumerate_matches (self->handle, query,
      (GumFoundApiFunc) gum_emit_match, &mc, &error);

  g_free (query);

  if (_gum_v8_maybe_throw (isolate, &error))
    return;

  mc.OnComplete ();
}

static gboolean
gum_emit_match (const GumApiDetails * details,
                GumV8MatchContext<GumV8ApiResolver> * mc)
{
  auto core = mc->parent->core;

  auto match = Object::New (core->isolate);
  _gum_v8_object_set_utf8 (match, "name", details->name, core);
  _gum_v8_object_set_pointer (match, "address", details->address, core);
  if (details->size != GUM_API_SIZE_NONE)
    _gum_v8_object_set_uint (match, "size", details->size, core);

  return mc->OnMatch (match);
}
