/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptmodule.h"

#include <string.h>

using namespace v8;

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptModule * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static void gum_script_module_on_enumerate_exports (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_script_module_handle_export_match (
    const GumExportDetails * details, gpointer user_data);
static const gchar * gum_export_type_to_string (GumExportType type);
static void gum_script_module_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_script_module_handle_range_match (
    const GumRangeDetails * details, gpointer user_data);
static void gum_script_module_on_find_base_address (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_module_on_find_export_by_name (
    const FunctionCallbackInfo<Value> & info);

void
_gum_script_module_init (GumScriptModule * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> module = ObjectTemplate::New (isolate);
  module->Set (String::NewFromUtf8 (isolate, "enumerateExports"),
      FunctionTemplate::New (isolate, gum_script_module_on_enumerate_exports,
      data));
  module->Set (String::NewFromUtf8 (isolate, "enumerateRanges"),
      FunctionTemplate::New (isolate, gum_script_module_on_enumerate_ranges,
      data));
  module->Set (String::NewFromUtf8 (isolate, "findBaseAddress"),
      FunctionTemplate::New (isolate, gum_script_module_on_find_base_address,
      data));
  module->Set (String::NewFromUtf8 (isolate, "findExportByName"),
      FunctionTemplate::New (isolate, gum_script_module_on_find_export_by_name,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Module"), module);
}

void
_gum_script_module_realize (GumScriptModule * self)
{
  (void) self;
}

void
_gum_script_module_dispose (GumScriptModule * self)
{
  (void) self;
}

void
_gum_script_module_finalize (GumScriptModule * self)
{
  (void) self;
}

static void
gum_script_module_on_enumerate_exports (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptModule *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  Local<Value> name_val = info[0];
  if (!name_val->IsString ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate,  "Module.enumerateExports: first argument must be "
        "a string specifying a module name whose exports to enumerate")));
    return;
  }
  String::Utf8Value name_str (name_val);

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "Module.enumerateExports: second argument must be "
        "a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  ctx.receiver = info.This ();

  gum_module_enumerate_exports (*name_str,
      gum_script_module_handle_export_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_script_module_handle_export_match (const GumExportDetails * details,
                                       gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);
  Isolate * isolate = ctx->isolate;

  Local<Object> exp (Object::New (isolate));
  exp->Set (String::NewFromUtf8 (isolate, "type"),
      String::NewFromUtf8 (isolate, gum_export_type_to_string (details->type)),
      ReadOnly);
  exp->Set (String::NewFromUtf8 (isolate, "name"),
      String::NewFromUtf8 (isolate, details->name), ReadOnly);
  exp->Set (String::NewFromUtf8 (isolate, "address"), _gum_script_pointer_new (
      GSIZE_TO_POINTER (details->address), ctx->self->core), ReadOnly);

  Handle<Value> argv[] = {
    exp
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static const gchar *
gum_export_type_to_string (GumExportType type)
{
  switch (type)
  {
    case GUM_EXPORT_FUNCTION: return "function";
    case GUM_EXPORT_VARIABLE: return "variable";
    default:
      break;
  }

  g_assert_not_reached ();
}

static void
gum_script_module_on_enumerate_ranges (const FunctionCallbackInfo<Value> & info)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptModule *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  Local<Value> name_val = info[0];
  if (!name_val->IsString ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate,  "Module.enumerateRanges: first argument must be "
        "a string specifying a module name whose ranges to enumerate")));
    return;
  }
  String::Utf8Value name_str (name_val);

  GumPageProtection prot;
  if (!_gum_script_page_protection_get (info[1], &prot, ctx.self->core))
    return;

  Local<Value> callbacks_value = info[2];
  if (!callbacks_value->IsObject ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "Module.enumerateRanges: third argument must be "
        "a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  ctx.receiver = info.This ();

  gum_module_enumerate_ranges (*name_str, prot,
      gum_script_module_handle_range_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_script_module_handle_range_match (const GumRangeDetails * details,
                                      gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);
  Isolate * isolate = ctx->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Local<Object> range (Object::New (isolate));
  range->Set (String::NewFromUtf8 (isolate, "base"), _gum_script_pointer_new (
      GSIZE_TO_POINTER (details->range->base_address), ctx->self->core),
      ReadOnly);
  range->Set (String::NewFromUtf8 (isolate, "size"),
      Integer::NewFromUnsigned (isolate, details->range->size), ReadOnly);
  range->Set (String::NewFromUtf8 (isolate, "protection"),
      String::NewFromUtf8 (isolate, prot_str), ReadOnly);

  Handle<Value> argv[] = {
    range
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static void
gum_script_module_on_find_base_address (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptModule * self = static_cast<GumScriptModule *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> module_name_val = info[0];
  if (!module_name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "Module.findBaseAddress: argument must be a string "
        "specifying module name")));
    return;
  }
  String::Utf8Value module_name (module_name_val);

  GumAddress raw_address = gum_module_find_base_address (*module_name);
  if (raw_address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_script_pointer_new (GSIZE_TO_POINTER (raw_address), self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_module_on_find_export_by_name (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptModule * self = static_cast<GumScriptModule *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> module_name_val = info[0];
  if (!module_name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "Module.findExportByName: first argument must be a string "
        "specifying module name")));
    return;
  }
  String::Utf8Value module_name (module_name_val);

  Local<Value> symbol_name_val = info[1];
  if (!symbol_name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "Module.findExportByName: second argument must be a string "
        "specifying name of exported symbol")));
    return;
  }
  String::Utf8Value symbol_name (symbol_name_val);

  GumAddress raw_address =
      gum_module_find_export_by_name (*module_name, *symbol_name);
  if (raw_address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_script_pointer_new (GSIZE_TO_POINTER (raw_address), self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}
