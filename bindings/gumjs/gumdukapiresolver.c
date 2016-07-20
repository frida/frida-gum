/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukapiresolver.h"

#include "gumdukmacros.h"

#include <gum/gumapiresolver.h>
#include <string.h>

typedef struct _GumDukMatchContext GumDukMatchContext;

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_api_resolver_construct)
GUMJS_DECLARE_FINALIZER (gumjs_api_resolver_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_api_resolver_enumerate_matches)
static gboolean gum_emit_match (const GumApiDetails * details,
    gpointer user_data);

static const duk_function_list_entry gumjs_api_resolver_functions[] =
{
  { "enumerateMatches", gumjs_api_resolver_enumerate_matches, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_api_resolver_init (GumDukApiResolver * self,
                            GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_api_resolver_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_api_resolver_functions);
  duk_push_c_function (ctx, gumjs_api_resolver_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->api_resolver = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "ApiResolver");
}

void
_gum_duk_api_resolver_dispose (GumDukApiResolver * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->api_resolver);
}

void
_gum_duk_api_resolver_finalize (GumDukApiResolver * self)
{
  (void) self;
}

static GumApiResolver *
gumjs_api_resolver_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumApiResolver * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_api_resolver_construct)
{
  const gchar * type;
  GumApiResolver * resolver;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new ApiResolver()` to create a new instance");
    duk_throw (ctx);
  }

  _gum_duk_args_parse (args, "s", &type);

  resolver = gum_api_resolver_make (type);
  if (resolver == NULL)
    _gum_duk_throw (ctx, "the specified ApiResolver is not available");

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, resolver);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_api_resolver_finalize)
{
  GumApiResolver * resolver;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "ApiResolver"))
    return 0;

  resolver = _gum_duk_steal_data (ctx, 0);
  if (resolver == NULL)
    return 0;

  g_object_unref (resolver);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_api_resolver_enumerate_matches)
{
  GumApiResolver * self;
  GumDukMatchContext mc;
  const gchar * query;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);
  GError * error;

  self = gumjs_api_resolver_from_args (args);

  _gum_duk_args_parse (args, "sF{onMatch,onComplete}", &query, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  error = NULL;
  gum_api_resolver_enumerate_matches (self, query, gum_emit_match, &mc, &error);
  if (error != NULL)
    goto invalid_query;
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;

invalid_query:
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
    duk_throw (ctx);
    return 0;
  }
}

static gboolean
gum_emit_match (const GumApiDetails * details,
                gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukScope * scope = mc->scope;
  GumDukCore * core = scope->core;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address), core);
  duk_put_prop_string (ctx, -2, "address");

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}
