/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscriptmodule.h"

#include <string.h>

using namespace v8;

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptModule * self;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static Handle<Value> gum_script_module_on_enumerate_exports (
    const Arguments & args);
static gboolean gum_script_module_handle_export_match (
    const GumExportDetails * details, gpointer user_data);
static const gchar * gum_export_type_to_string (GumExportType type);
static Handle<Value> gum_script_module_on_enumerate_ranges (
    const Arguments & args);
static gboolean gum_script_module_handle_range_match (
    const GumRangeDetails * details, gpointer user_data);
static Handle<Value> gum_script_module_on_find_base_address (
    const Arguments & args);
static Handle<Value> gum_script_module_on_find_export_by_name (
    const Arguments & args);

void
_gum_script_module_init (GumScriptModule * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  self->core = core;

  Handle<ObjectTemplate> module = ObjectTemplate::New ();
  module->Set (String::New ("enumerateExports"),
      FunctionTemplate::New (gum_script_module_on_enumerate_exports,
      External::Wrap (self)));
  module->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_module_on_enumerate_ranges,
      External::Wrap (self)));
  module->Set (String::New ("findBaseAddress"),
      FunctionTemplate::New (gum_script_module_on_find_base_address,
      External::Wrap (self)));
  module->Set (String::New ("findExportByName"),
      FunctionTemplate::New (gum_script_module_on_find_export_by_name,
      External::Wrap (self)));
  scope->Set (String::New ("Module"), module);
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

static Handle<Value>
gum_script_module_on_enumerate_exports (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptModule *> (External::Unwrap (args.Data ()));

  Local<Value> name_val = args[0];
  if (!name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateExports: first argument must be a string "
        "specifying a module name whose exports to enumerate")));
    return Undefined ();
  }
  String::Utf8Value name_str (name_val);

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateExports: second argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_module_enumerate_exports (*name_str,
      gum_script_module_handle_export_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_module_handle_export_match (const GumExportDetails * details,
                                       gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Local<Object> exp (Object::New ());
  exp->Set (String::New ("type"),
      String::New (gum_export_type_to_string (details->type)), ReadOnly);
  exp->Set (String::New ("name"),
      String::New (details->name), ReadOnly);
  exp->Set (String::New ("address"), _gum_script_pointer_new (ctx->self->core,
      GSIZE_TO_POINTER (details->address)), ReadOnly);

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
  return NULL;
}

static Handle<Value>
gum_script_module_on_enumerate_ranges (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptModule *> (External::Unwrap (args.Data ()));

  Local<Value> name_val = args[0];
  if (!name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateRanges: first argument must be a string "
        "specifying a module name whose ranges to enumerate")));
    return Undefined ();
  }
  String::Utf8Value name_str (name_val);

  GumPageProtection prot;
  if (!_gum_script_page_protection_get (args[1], &prot))
    return Undefined ();

  Local<Value> callbacks_value = args[2];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateRanges: third argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_module_enumerate_ranges (*name_str, prot,
      gum_script_module_handle_range_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_module_handle_range_match (const GumRangeDetails * details,
                                      gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Local<Object> range (Object::New ());
  range->Set (String::New ("base"), _gum_script_pointer_new (ctx->self->core,
      GSIZE_TO_POINTER (details->range->base_address)), ReadOnly);
  range->Set (String::New ("size"),
      Integer::NewFromUnsigned (details->range->size), ReadOnly);
  range->Set (String::New ("protection"), String::New (prot_str), ReadOnly);

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

static Handle<Value>
gum_script_module_on_find_base_address (const Arguments & args)
{
  GumScriptModule * self = static_cast<GumScriptModule *> (
      External::Unwrap (args.Data ()));

  Local<Value> module_name_val = args[0];
  if (!module_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findBaseAddress: argument must be a string "
        "specifying module name")));
    return Undefined ();
  }
  String::Utf8Value module_name (module_name_val);

  GumAddress raw_address = gum_module_find_base_address (*module_name);
  if (raw_address == 0)
    return Null ();

  return _gum_script_pointer_new (self->core, GSIZE_TO_POINTER (raw_address));
}

static Handle<Value>
gum_script_module_on_find_export_by_name (const Arguments & args)
{
  GumScriptModule * self = static_cast<GumScriptModule *> (
      External::Unwrap (args.Data ()));

  Local<Value> module_name_val = args[0];
  if (!module_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findExportByName: first argument must be a string "
        "specifying module name")));
    return Undefined ();
  }
  String::Utf8Value module_name (module_name_val);

  Local<Value> symbol_name_val = args[1];
  if (!symbol_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findExportByName: second argument must be a string "
        "specifying name of exported symbol")));
    return Undefined ();
  }
  String::Utf8Value symbol_name (symbol_name_val);

  GumAddress raw_address =
      gum_module_find_export_by_name (*module_name, *symbol_name);
  if (raw_address == 0)
    return Null ();

  return _gum_script_pointer_new (self->core, GSIZE_TO_POINTER (raw_address));
}

