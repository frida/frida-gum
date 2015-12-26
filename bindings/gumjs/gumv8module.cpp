/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8module.h"

#include <gum/gum-init.h>
#include <string.h>

using namespace v8;

typedef struct _GumV8ImportsContext GumV8ImportsContext;
typedef struct _GumV8ExportsContext GumV8ExportsContext;
typedef struct _GumV8RangesContext GumV8RangesContext;

struct _GumV8ImportsContext
{
  GumV8Module * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;

  Local<Object> imp;
  Local<Value> type;
  Local<Value> name;
  Local<Value> module;
  Local<Value> address;
  Local<Value> variable;
};

struct _GumV8ExportsContext
{
  GumV8Module * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;

  Local<Object> exp;
  Local<Value> type;
  Local<Value> name;
  Local<Value> address;
  Local<Value> variable;
};

struct _GumV8RangesContext
{
  GumV8Module * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static void gum_v8_module_on_enumerate_imports (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_module_handle_import_match (
    const GumImportDetails * details, gpointer user_data);
static void gum_v8_module_on_enumerate_exports (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_module_handle_export_match (
    const GumExportDetails * details, gpointer user_data);
static void gum_v8_module_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_module_handle_range_match (
    const GumRangeDetails * details, gpointer user_data);
static void gum_v8_module_on_find_base_address (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_module_on_find_export_by_name (
    const FunctionCallbackInfo<Value> & info);

class GumV8ModuleEternals
{
public:
  v8::Eternal<v8::Object> imp;
  v8::Eternal<v8::Object> exp;

  v8::Eternal<v8::String> type;
  v8::Eternal<v8::String> name;
  v8::Eternal<v8::String> module;
  v8::Eternal<v8::String> address;
  v8::Eternal<v8::String> variable;
};

static GumV8ModuleEternals * eternals;

static void
gum_v8_module_deinit_eternals (void)
{
  delete eternals;
  eternals = nullptr;
}

void
_gum_v8_module_init (GumV8Module * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> module = ObjectTemplate::New (isolate);
  module->Set (String::NewFromUtf8 (isolate, "enumerateImports"),
      FunctionTemplate::New (isolate, gum_v8_module_on_enumerate_imports,
      data));
  module->Set (String::NewFromUtf8 (isolate, "enumerateExports"),
      FunctionTemplate::New (isolate, gum_v8_module_on_enumerate_exports,
      data));
  module->Set (String::NewFromUtf8 (isolate, "enumerateRanges"),
      FunctionTemplate::New (isolate, gum_v8_module_on_enumerate_ranges,
      data));
  module->Set (String::NewFromUtf8 (isolate, "findBaseAddress"),
      FunctionTemplate::New (isolate, gum_v8_module_on_find_base_address,
      data));
  module->Set (String::NewFromUtf8 (isolate, "findExportByName"),
      FunctionTemplate::New (isolate, gum_v8_module_on_find_export_by_name,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Module"), module);
}

void
_gum_v8_module_realize (GumV8Module * self)
{
  static gsize gonce_value = 0;

  if (g_once_init_enter (&gonce_value))
  {
    Isolate * isolate = self->core->isolate;
    Local<Context> context = isolate->GetCurrentContext ();

    Local<String> type (String::NewFromUtf8 (isolate, "type"));
    Local<String> name (String::NewFromUtf8 (isolate, "name"));
    Local<String> module (String::NewFromUtf8 (isolate, "module"));
    Local<String> address (String::NewFromUtf8 (isolate, "address"));

    Local<String> function (String::NewFromUtf8 (isolate, "function"));
    Local<String> variable (String::NewFromUtf8 (isolate, "variable"));

    Local<String> empty_string = String::NewFromUtf8 (isolate, "");

    Local<Object> imp (Object::New (isolate));
    Maybe<bool> result = imp->ForceSet (context, type, function);
    g_assert (result.IsJust ());
    result = imp->ForceSet (context, name, empty_string, DontDelete);
    g_assert (result.IsJust ());
    result = imp->ForceSet (context, module, empty_string);
    g_assert (result.IsJust ());
    result = imp->ForceSet (context, address, _gum_v8_native_pointer_new (
        GSIZE_TO_POINTER (NULL), self->core));
    g_assert (result.IsJust ());

    Local<Object> exp (Object::New (isolate));
    result = exp->ForceSet (context, type, function, DontDelete);
    g_assert (result.IsJust ());
    result = exp->ForceSet (context, name, empty_string, DontDelete);
    g_assert (result.IsJust ());
    result = exp->ForceSet (context, address, _gum_v8_native_pointer_new (
        GSIZE_TO_POINTER (NULL), self->core), DontDelete);
    g_assert (result.IsJust ());

    eternals = new GumV8ModuleEternals ();
    eternals->imp.Set (isolate, imp);
    eternals->exp.Set (isolate, exp);

    eternals->type.Set (isolate, type);
    eternals->name.Set (isolate, name);
    eternals->module.Set (isolate, module);
    eternals->address.Set (isolate, address);
    eternals->variable.Set (isolate, variable);

    _gum_register_destructor (gum_v8_module_deinit_eternals);

    g_once_init_leave (&gonce_value, 1);
  }
}

void
_gum_v8_module_dispose (GumV8Module * self)
{
  (void) self;
}

void
_gum_v8_module_finalize (GumV8Module * self)
{
  (void) self;
}

/*
 * Prototype:
 * Module.enumerateImports(name, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_module_on_enumerate_imports (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Module * self = static_cast<GumV8Module *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();
  GumV8ImportsContext ctx;

  ctx.self = self;
  ctx.isolate = isolate;

  Local<Value> name_val = info[0];
  if (!name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Module.enumerateImports: first argument must be "
        "a string specifying a module name whose imports to enumerate")));
    return;
  }
  String::Utf8Value name_str (name_val);

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Module.enumerateImports: second argument must be "
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

  ctx.receiver = info.This ();

  ctx.imp = eternals->imp.Get (isolate);
  ctx.type = eternals->type.Get (isolate);
  ctx.name = eternals->name.Get (isolate);
  ctx.module = eternals->module.Get (isolate);
  ctx.address = eternals->address.Get (isolate);
  ctx.variable = eternals->variable.Get (isolate);

  gum_module_enumerate_imports (*name_str,
      gum_v8_module_handle_import_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_v8_module_handle_import_match (const GumImportDetails * details,
                                   gpointer user_data)
{
  GumV8ImportsContext * ctx =
      static_cast<GumV8ImportsContext *> (user_data);
  Isolate * isolate = ctx->isolate;
  Local<Context> jc = isolate->GetCurrentContext ();
  PropertyAttribute attrs =
      static_cast<PropertyAttribute> (ReadOnly | DontDelete);

  Local<Object> imp (ctx->imp->Clone ());

  switch (details->type)
  {
    case GUM_IMPORT_FUNCTION:
    {
      /* the default value in our template */
      break;
    }
    case GUM_IMPORT_VARIABLE:
    {
      Maybe<bool> success = imp->ForceSet (jc, ctx->type, ctx->variable, attrs);
      g_assert (success.IsJust ());
      break;
    }
    case GUM_IMPORT_UNKNOWN:
    {
      Maybe<bool> success = imp->Delete (jc, ctx->type);
      g_assert (success.IsJust ());
      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }

  Maybe<bool> success = imp->ForceSet (jc,
      ctx->name,
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> (details->name)),
      attrs);
  g_assert (success.IsJust ());

  if (details->module != NULL)
  {
    success = imp->ForceSet (jc,
        ctx->module,
        String::NewFromOneByte (isolate,
            reinterpret_cast<const uint8_t *> (details->module)),
        attrs);
    g_assert (success.IsJust ());
  }
  else
  {
    success = imp->Delete (jc, ctx->module);
    g_assert (success.IsJust ());
  }

  if (details->address != 0)
  {
    success = imp->ForceSet (jc,
        ctx->address,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address),
            ctx->self->core),
        attrs);
    g_assert (success.IsJust ());
  }
  else
  {
    success = imp->Delete (jc, ctx->address);
    g_assert (success.IsJust ());
  }

  Handle<Value> argv[] = {
    imp
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

/*
 * Prototype:
 * Module.enumerateExports(name, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_module_on_enumerate_exports (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Module * self = static_cast<GumV8Module *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();
  GumV8ExportsContext ctx;

  ctx.self = self;
  ctx.isolate = isolate;

  Local<Value> name_val = info[0];
  if (!name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Module.enumerateExports: first argument must be "
        "a string specifying a module name whose exports to enumerate")));
    return;
  }
  String::Utf8Value name_str (name_val);

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Module.enumerateExports: second argument must be "
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

  ctx.receiver = info.This ();

  ctx.exp = eternals->exp.Get (isolate);
  ctx.type = eternals->type.Get (isolate);
  ctx.name = eternals->name.Get (isolate);
  ctx.address = eternals->address.Get (isolate);
  ctx.variable = eternals->variable.Get (isolate);

  gum_module_enumerate_exports (*name_str,
      gum_v8_module_handle_export_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_v8_module_handle_export_match (const GumExportDetails * details,
                                   gpointer user_data)
{
  GumV8ExportsContext * ctx =
      static_cast<GumV8ExportsContext *> (user_data);
  Isolate * isolate = ctx->isolate;
  Local<Context> jc = isolate->GetCurrentContext ();
  PropertyAttribute attrs =
      static_cast<PropertyAttribute> (ReadOnly | DontDelete);

  Local<Object> exp (ctx->exp->Clone ());

  if (details->type != GUM_EXPORT_FUNCTION)
  {
    Maybe<bool> success = exp->ForceSet (jc, ctx->type, ctx->variable, attrs);
    g_assert (success.IsJust ());
  }

  Maybe<bool> success = exp->ForceSet (jc,
      ctx->name,
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> (details->name)),
      attrs);
  g_assert (success.IsJust ());

  success = exp->ForceSet (jc,
      ctx->address,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address),
          ctx->self->core),
      attrs);
  g_assert (success.IsJust ());

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

/*
 * Prototype:
 * Module.enumerateRanges(name, prot, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_module_on_enumerate_ranges (const FunctionCallbackInfo<Value> & info)
{
  GumV8RangesContext ctx;

  ctx.self = static_cast<GumV8Module *> (
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
  if (!_gum_v8_page_protection_get (info[1], &prot, ctx.self->core))
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

  ctx.receiver = info.This ();

  gum_module_enumerate_ranges (*name_str, prot,
      gum_v8_module_handle_range_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_v8_module_handle_range_match (const GumRangeDetails * details,
                                  gpointer user_data)
{
  GumV8RangesContext * ctx =
      static_cast<GumV8RangesContext *> (user_data);
  GumV8Core * core = ctx->self->core;
  Isolate * isolate = ctx->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Local<Object> range (Object::New (isolate));
  _gum_v8_object_set_pointer (range, "base", details->range->base_address, core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_ascii (range, "protection", prot_str, core);

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

/*
 * Prototype:
 * Module.findBaseAddress(module_name)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_module_on_find_base_address (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Module * self = static_cast<GumV8Module *> (
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
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (raw_address), self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

/*
 * Prototype:
 * Module.findExportByName(module_name, symbol_name)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_module_on_find_export_by_name (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Module * self = static_cast<GumV8Module *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> module_name_val = info[0];
  gchar * module_name;
  if (module_name_val->IsString ())
  {
    String::Utf8Value module_name_utf8 (module_name_val);
    module_name = g_strdup (*module_name_utf8);
  }
  else if (module_name_val->IsNull ())
  {
    module_name = NULL;
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "Module.findExportByName: first argument must be a string "
        "specifying module name, or null")));
    return;
  }

  Local<Value> symbol_name_val = info[1];
  if (!symbol_name_val->IsString ())
  {
    g_free (module_name);
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "Module.findExportByName: second argument must be a string "
        "specifying name of exported symbol")));
    return;
  }
  String::Utf8Value symbol_name (symbol_name_val);

  GumAddress raw_address =
      gum_module_find_export_by_name (module_name, *symbol_name);
  if (raw_address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (raw_address), self->core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (module_name);
}
