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
  Local<Value> type;
  Local<Value> name;
  Local<Value> module;
  Local<Value> address;
  Local<Value> variable;

  GumV8Core * core;
  Isolate * isolate;
  Local<Context> context;

  gboolean has_pending_exception;
};

struct GumV8ExportsContext
{
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Value> receiver;

  Local<Object> exp;
  Local<Value> type;
  Local<Value> name;
  Local<Value> address;
  Local<Value> variable;

  GumV8Core * core;
  Isolate * isolate;
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
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto object = _gum_v8_create_module ("Module", scope, isolate);
  _gum_v8_module_add (module, object, gumjs_module_functions, isolate);
}

void
_gum_v8_module_realize (GumV8Module * self)
{
  static gsize gonce_value = 0;

  if (g_once_init_enter (&gonce_value))
  {
    auto isolate = self->core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto type = _gum_v8_string_new_from_ascii ("type", isolate);
    auto name = _gum_v8_string_new_from_ascii ("name", isolate);
    auto module = _gum_v8_string_new_from_ascii ("module", isolate);
    auto address = _gum_v8_string_new_from_ascii ("address", isolate);

    auto function = _gum_v8_string_new_from_ascii ("function", isolate);
    auto variable = _gum_v8_string_new_from_ascii ("variable", isolate);

    auto empty_string = String::Empty (isolate);

    auto imp = Object::New (isolate);
    imp->ForceSet (context, type, function).FromJust ();
    imp->ForceSet (context, name, empty_string, DontDelete).FromJust ();
    imp->ForceSet (context, module, empty_string).FromJust ();
    imp->ForceSet (context, address, _gum_v8_native_pointer_new (
        GSIZE_TO_POINTER (NULL), self->core)).FromJust ();

    auto exp = Object::New (isolate);
    exp->ForceSet (context, type, function, DontDelete).FromJust ();
    exp->ForceSet (context, name, empty_string, DontDelete).FromJust ();
    exp->ForceSet (context, address, _gum_v8_native_pointer_new (
        GSIZE_TO_POINTER (NULL), self->core), DontDelete).FromJust ();

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
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumV8ImportsContext ic;
  gchar * name;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ic.on_match,
      &ic.on_complete))
    return;
  ic.receiver = Undefined (isolate);

  ic.imp = eternals->imp.Get (isolate);
  ic.type = eternals->type.Get (isolate);
  ic.name = eternals->name.Get (isolate);
  ic.module = eternals->module.Get (isolate);
  ic.address = eternals->address.Get (isolate);
  ic.variable = eternals->variable.Get (isolate);

  ic.core = core;
  ic.isolate = isolate;
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
  auto isolate = ic->isolate;
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
      _gum_v8_string_new_from_ascii (details->name, isolate), attrs)
      .FromJust ();

  if (details->module != NULL)
  {
    imp->ForceSet (context, ic->module,
        _gum_v8_string_new_from_ascii (details->module, isolate), attrs)
        .FromJust ();
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
  GumV8ExportsContext ec;
  gchar * name;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ec.on_match,
      &ec.on_complete))
    return;
  ec.receiver = Undefined (isolate);

  ec.exp = eternals->exp.Get (isolate);
  ec.type = eternals->type.Get (isolate);
  ec.name = eternals->name.Get (isolate);
  ec.address = eternals->address.Get (isolate);
  ec.variable = eternals->variable.Get (isolate);

  ec.core = core;
  ec.isolate = isolate;
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
  auto isolate = ec->isolate;
  auto context = ec->context;

  auto exp = ec->exp->Clone ();

  auto attrs = (PropertyAttribute) (ReadOnly | DontDelete);

  if (details->type != GUM_EXPORT_FUNCTION)
  {
    exp->ForceSet (context, ec->type, ec->variable, attrs).FromJust ();
  }

  exp->ForceSet (context, ec->name,
      _gum_v8_string_new_from_ascii (details->name, isolate), attrs)
      .FromJust ();

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
  GumV8RangesContext rc;
  gchar * name;
  GumPageProtection prot;
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
