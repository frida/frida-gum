/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8apiresolver.h"

#include "gumv8macros.h"

#include <string.h>

#define GUMJS_MODULE_NAME ApiResolver

using namespace v8;

struct GumV8MatchContext
{
  Local<Function> on_match;
  Local<Function> on_complete;

  GumV8Core * core;

  gboolean has_pending_exception;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_api_resolver_construct);
GUMJS_DECLARE_FUNCTION (gumjs_api_resolver_enumerate_matches)
static gboolean gum_emit_match (const GumApiDetails * details,
    GumV8MatchContext * mc);

static const GumV8Function gumjs_api_resolver_functions[] =
{
  { "enumerateMatches", gumjs_api_resolver_enumerate_matches },

  { NULL, NULL }
};

void
_gum_v8_api_resolver_init (GumV8ApiResolver * self,
                           GumV8Core * core,
                           Handle<ObjectTemplate> scope)
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
  (void) self;
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
  isolate->Exit ();
  {
    Unlocker ul (isolate);
    resolver = gum_api_resolver_make (type);
  }
  isolate->Enter ();

  g_free (type);

  if (resolver == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "The specified ApiResolver is not available");
    return;
  }

  gum_v8_object_manager_add (&module->objects, wrapper, resolver, module);
}

/*
 * Prototype:
 * ApiResolver.enumerateMatches(query, callbacks)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_CLASS_METHOD (gumjs_api_resolver_enumerate_matches,
                           GumV8ApiResolverObject)
{
  gchar * query;
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &query, &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  GError * error = NULL;
  gum_api_resolver_enumerate_matches (self->handle, query,
      (GumFoundApiFunc) gum_emit_match, &mc, &error);

  g_free (query);

  if (error != NULL)
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);
    return;
  }

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_match (const GumApiDetails * details,
                GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto match = Object::New (isolate);
  _gum_v8_object_set_utf8 (match, "name", details->name, core);
  _gum_v8_object_set_pointer (match, "address", details->address, core);

  Handle<Value> argv[] = { match };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}
