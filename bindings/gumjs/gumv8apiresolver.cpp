/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8apiresolver.h"

#include <gum/gumapiresolver.h>
#include <string.h>

using namespace v8;

typedef struct _GumV8MatchContext GumV8MatchContext;

struct _GumV8MatchContext
{
  GumV8ApiResolver * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
};

static void gum_v8_api_resolver_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_api_resolver_on_enumerate_matches (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_api_resolver_handle_module_match (
    const GumApiDetails * details, gpointer user_data);
static void gum_v8_api_resolver_on_weak_notify (
    const WeakCallbackInfo<GumV8ApiResolver> & info);
static void gum_v8_api_resolver_handle_free (gpointer data);

void
_gum_v8_api_resolver_init (GumV8ApiResolver * self,
                           GumV8Core * core,
                           Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Local<FunctionTemplate> api_resolver = FunctionTemplate::New (isolate,
      gum_v8_api_resolver_on_new, data);
  api_resolver->SetClassName (String::NewFromUtf8 (isolate, "ApiResolver"));
  Local<ObjectTemplate> api_resolver_proto = api_resolver->PrototypeTemplate ();
  api_resolver_proto->Set (String::NewFromUtf8 (isolate, "enumerateMatches"),
      FunctionTemplate::New (isolate, gum_v8_api_resolver_on_enumerate_matches,
      data));
  api_resolver->InstanceTemplate ()->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, "ApiResolver"), api_resolver);
}

void
_gum_v8_api_resolver_realize (GumV8ApiResolver * self)
{
  self->resolvers = g_hash_table_new_full (NULL, NULL, g_object_unref,
      gum_v8_api_resolver_handle_free);
}

void
_gum_v8_api_resolver_dispose (GumV8ApiResolver * self)
{
  g_clear_pointer (&self->resolvers, g_hash_table_unref);
}

void
_gum_v8_api_resolver_finalize (GumV8ApiResolver * self)
{
  (void) self;
}

static void
gum_v8_api_resolver_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8ApiResolver * self = static_cast<GumV8ApiResolver *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new ApiResolver()` to create a new instance")));
    return;
  }

  Local<Value> type_val = info[0];
  if (!type_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "ApiResolver: first argument must be a string specifying type")));
    return;
  }
  String::Utf8Value type (type_val);

  GumApiResolver * resolver = gum_api_resolver_make (*type);
  if (resolver == NULL)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "The specified ApiResolver is not available")));
    return;
  }

  Local<Object> instance (info.Holder ());
  instance->SetAlignedPointerInInternalField (0, resolver);
  instance->SetAlignedPointerInInternalField (1, self);

  GumPersistent<v8::Object>::type * instance_handle =
      new GumPersistent<Object>::type (self->core->isolate, instance);
  instance_handle->MarkIndependent ();
  instance_handle->SetWeak (self, gum_v8_api_resolver_on_weak_notify,
      WeakCallbackType::kInternalFields);

  g_hash_table_insert (self->resolvers, resolver, instance_handle);
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
static void
gum_v8_api_resolver_on_enumerate_matches (
    const FunctionCallbackInfo<Value> & info)
{
  GumApiResolver * api_resolver = static_cast<GumApiResolver *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumV8MatchContext ctx;

  ctx.self = static_cast<GumV8ApiResolver *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  Local<Value> query_val = info[0];
  if (!query_val->IsString ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "ApiResolver.enumerateMatches: first argument must be "
        "a string specifying a resolver-specific query")));
    return;
  }
  String::Utf8Value query (query_val);

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "ApiResolver.enumerateMatches: second argument must be "
        "a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_v8_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_v8_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  GError * error = NULL;
  gum_api_resolver_enumerate_matches (api_resolver, *query,
      gum_v8_api_resolver_handle_module_match, &ctx, &error);
  if (error != NULL)
  {
    gchar * message = g_strdup_printf ("ApiResolver.enumerateMatches: %s",
        error->message);
    ctx.isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
        ctx.isolate, message)));
    g_free (message);
    g_error_free (error);
    return;
  }

  ctx.on_complete->Call (Undefined (ctx.isolate), 0, 0);
}

static gboolean
gum_v8_api_resolver_handle_module_match (const GumApiDetails * details,
                                         gpointer user_data)
{
  GumV8MatchContext * ctx =
      static_cast<GumV8MatchContext *> (user_data);
  GumV8Core * core = ctx->self->core;
  Isolate * isolate = ctx->isolate;

  Local<Object> match (Object::New (isolate));
  _gum_v8_object_set_utf8 (match, "name", details->name, core);
  _gum_v8_object_set_pointer (match, "address", details->address, core);

  Handle<Value> argv[] = {
    match
  };
  Local<Value> result = ctx->on_match->Call (Undefined (isolate), 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static void
gum_v8_api_resolver_on_weak_notify (
    const WeakCallbackInfo<GumV8ApiResolver> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumApiResolver * resolver = static_cast<GumApiResolver *> (
      info.GetInternalField (0));
  GumV8ApiResolver * module = static_cast<GumV8ApiResolver *> (
      info.GetInternalField (1));
  g_hash_table_remove (module->resolvers, resolver);
}

static void
gum_v8_api_resolver_handle_free (gpointer data)
{
  GumPersistent<v8::Object>::type * instance_handle =
      static_cast<GumPersistent<v8::Object>::type *> (data);
  delete instance_handle;
}
