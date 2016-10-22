/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8module.h"

#include "gumv8macros.h"

#include <gum/gum-init.h>
#include <string.h>

#define GUMJS_MODULE_NAME Module

using namespace v8;

struct GumV8ImportsContext
{
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Value> receiver;

  Local<Object> imp;
  Local<String> type;
  Local<String> name;
  Local<String> module;
  Local<String> address;
  Local<String> variable;

  GumV8Core * core;
  Local<Context> context;

  gboolean has_pending_exception;
};

struct GumV8ExportsContext
{
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Value> receiver;

  Local<Object> exp;
  Local<String> type;
  Local<String> name;
  Local<String> address;
  Local<String> variable;

  GumV8Core * core;
  Local<Context> context;

  gboolean has_pending_exception;
};

struct GumV8RangesContext
{
  Local<Function> on_match;
  Local<Function> on_complete;

  GumV8Core * core;

  gboolean has_pending_exception;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumV8ImportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumV8ExportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8RangesContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

static const GumV8Function gumjs_module_functions[] =
{
  { "enumerateImports", gumjs_module_enumerate_imports },
  { "enumerateExports", gumjs_module_enumerate_exports },
  { "enumerateRanges", gumjs_module_enumerate_ranges },
  { "findBaseAddress", gumjs_module_find_base_address },
  { "findExportByName", gumjs_module_find_export_by_name },

  { NULL, NULL }
};

void
_gum_v8_module_init (GumV8Module * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto object = _gum_v8_create_module ("Module", scope, isolate);
  _gum_v8_module_add (module, object, gumjs_module_functions, isolate);
}

void
_gum_v8_module_realize (GumV8Module * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto type_key = _gum_v8_string_new_ascii (isolate, "type");
  self->type_key = new GumPersistent<String>::type (isolate, type_key);
  auto name_key = _gum_v8_string_new_ascii (isolate, "name");
  self->name_key = new GumPersistent<String>::type (isolate, name_key);
  auto module_key = _gum_v8_string_new_ascii (isolate, "module");
  self->module_key = new GumPersistent<String>::type (isolate, module_key);
  auto address_key = _gum_v8_string_new_ascii (isolate, "address");
  self->address_key = new GumPersistent<String>::type (isolate, address_key);

  auto function_value = _gum_v8_string_new_ascii (isolate, "function");
  auto variable_value = _gum_v8_string_new_ascii (isolate, "variable");
  self->variable_value = new GumPersistent<String>::type (isolate,
      variable_value);

  auto empty_string = String::Empty (isolate);

  auto imp = Object::New (isolate);
  imp->ForceSet (context, type_key, function_value).FromJust ();
  imp->ForceSet (context, name_key, empty_string, DontDelete).FromJust ();
  imp->ForceSet (context, module_key, empty_string).FromJust ();
  imp->ForceSet (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->import_value = new GumPersistent<Object>::type (isolate, imp);

  auto exp = Object::New (isolate);
  exp->ForceSet (context, type_key, function_value, DontDelete)
      .FromJust ();
  exp->ForceSet (context, name_key, empty_string, DontDelete).FromJust ();
  exp->ForceSet (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core), DontDelete).FromJust ();
  self->export_value = new GumPersistent<Object>::type (isolate, exp);
}

void
_gum_v8_module_dispose (GumV8Module * self)
{
  delete self->import_value;
  delete self->export_value;
  self->import_value = nullptr;
  self->export_value = nullptr;

  delete self->type_key;
  delete self->name_key;
  delete self->module_key;
  delete self->address_key;
  delete self->variable_value;
  self->type_key = nullptr;
  self->name_key = nullptr;
  self->module_key = nullptr;
  self->address_key = nullptr;
  self->variable_value = nullptr;
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
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  gchar * name;
  GumV8ImportsContext ic;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ic.on_match,
      &ic.on_complete))
    return;
  ic.receiver = Undefined (isolate);

  ic.imp = Local<Object>::New (isolate, *module->import_value);
  ic.type = Local<String>::New (isolate, *module->type_key);
  ic.name = Local<String>::New (isolate, *module->name_key);
  ic.module = Local<String>::New (isolate, *module->module_key);
  ic.address = Local<String>::New (isolate, *module->address_key);
  ic.variable = Local<String>::New (isolate, *module->variable_value);

  ic.core = core;
  ic.context = isolate->GetCurrentContext ();

  ic.has_pending_exception = FALSE;

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &ic);

  if (!ic.has_pending_exception)
  {
    ic.on_complete->Call (ic.receiver, 0, nullptr);
  }

  g_free (name);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumV8ImportsContext * ic)
{
  auto core = ic->core;
  auto isolate = core->isolate;
  auto context = ic->context;

  auto imp = ic->imp->Clone ();

  auto attrs = (PropertyAttribute) (ReadOnly | DontDelete);

  switch (details->type)
  {
    case GUM_IMPORT_FUNCTION:
    {
      /* the default value in our template */
      break;
    }
    case GUM_IMPORT_VARIABLE:
    {
      imp->ForceSet (context, ic->type, ic->variable, attrs).FromJust ();
      break;
    }
    case GUM_IMPORT_UNKNOWN:
    {
      imp->Delete (context, ic->type).FromJust ();
      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }

  imp->ForceSet (context, ic->name,
      _gum_v8_string_new_ascii (isolate, details->name), attrs).FromJust ();

  if (details->module != NULL)
  {
    imp->ForceSet (context, ic->module,
        _gum_v8_string_new_ascii (isolate, details->module), attrs).FromJust ();
  }
  else
  {
    imp->Delete (context, ic->module).FromJust ();
  }

  if (details->address != 0)
  {
    imp->ForceSet (context, ic->address,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core),
        attrs).FromJust ();
  }
  else
  {
    imp->Delete (context, ic->address).FromJust ();
  }

  Handle<Value> argv[] = { imp };
  auto result = ic->on_match->Call (ic->receiver, G_N_ELEMENTS (argv), argv);

  ic->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !ic->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
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
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  gchar * name;
  GumV8ExportsContext ec;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ec.on_match,
      &ec.on_complete))
    return;
  ec.receiver = Undefined (isolate);

  ec.exp = Local<Object>::New (isolate, *module->export_value);
  ec.type = Local<String>::New (isolate, *module->type_key);
  ec.name = Local<String>::New (isolate, *module->name_key);
  ec.address = Local<String>::New (isolate, *module->address_key);
  ec.variable = Local<String>::New (isolate, *module->variable_value);

  ec.core = core;
  ec.context = isolate->GetCurrentContext ();

  ec.has_pending_exception = FALSE;

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &ec);

  if (!ec.has_pending_exception)
  {
    ec.on_complete->Call (ec.receiver, 0, nullptr);
  }

  g_free (name);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumV8ExportsContext * ec)
{
  auto core = ec->core;
  auto isolate = core->isolate;
  auto context = ec->context;

  auto exp = ec->exp->Clone ();

  auto attrs = (PropertyAttribute) (ReadOnly | DontDelete);

  if (details->type != GUM_EXPORT_FUNCTION)
  {
    exp->ForceSet (context, ec->type, ec->variable, attrs).FromJust ();
  }

  exp->ForceSet (context, ec->name,
      _gum_v8_string_new_ascii (isolate, details->name), attrs).FromJust ();

  exp->ForceSet (context, ec->address,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core),
      attrs).FromJust ();

  Handle<Value> argv[] = { exp };
  auto result = ec->on_match->Call (ec->receiver, G_N_ELEMENTS (argv), argv);

  ec->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !ec->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
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
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  gchar * name;
  GumPageProtection prot;
  GumV8RangesContext rc;
  if (!_gum_v8_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &rc.on_match, &rc.on_complete))
    return;
  rc.core = core;

  rc.has_pending_exception = FALSE;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &rc);

  if (!rc.has_pending_exception)
  {
    rc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }

  g_free (name);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8RangesContext * rc)
{
  auto core = rc->core;
  auto isolate = core->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_ascii (range, "protection", prot_str, core);

  Handle<Value> argv[] = { range };
  auto result =
      rc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  rc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !rc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
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
GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  auto address = gum_module_find_base_address (name);
  if (address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (name);
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
GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  gchar * module_name, * symbol_name;
  if (!_gum_v8_args_parse (args, "s?s", &module_name, &symbol_name))
    return;

  auto address = gum_module_find_export_by_name (module_name, symbol_name);
  if (address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (module_name);
  g_free (symbol_name);
}
