/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
  Local<String> slot;
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

struct GumV8MatchContext
{
  Local<Function> on_match;
  Local<Function> on_complete;

  GumV8Core * core;

  gboolean has_pending_exception;
};

struct GumV8ModuleMap
{
  GumPersistent<Object>::type * wrapper;
  GumModuleMap * handle;

  GumV8Module * module;
};

struct GumV8ModuleFilter
{
  GumPersistent<Function>::type * callback;

  GumV8Core * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumV8ImportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumV8ExportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_map_construct)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_has)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_path)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_update)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_copy_values)

static GumV8ModuleMap * gum_v8_module_map_new (Handle<Object> wrapper,
    GumModuleMap * handle, GumV8Module * module);
static void gum_v8_module_map_free (GumV8ModuleMap * self);
static void gum_v8_module_map_on_weak_notify (
    const WeakCallbackInfo<GumV8ModuleMap> & info);

static void gum_v8_module_filter_free (GumV8ModuleFilter * filter);
static gboolean gum_v8_module_filter_matches (const GumModuleDetails * details,
    GumV8ModuleFilter * self);

static const GumV8Function gumjs_module_functions[] =
{
  { "ensureInitialized", gumjs_module_ensure_initialized },
  { "enumerateImports", gumjs_module_enumerate_imports },
  { "enumerateExports", gumjs_module_enumerate_exports },
  { "enumerateSymbols", gumjs_module_enumerate_symbols },
  { "enumerateRanges", gumjs_module_enumerate_ranges },
  { "findBaseAddress", gumjs_module_find_base_address },
  { "findExportByName", gumjs_module_find_export_by_name },

  { NULL, NULL }
};

static const GumV8Function gumjs_module_map_functions[] =
{
  { "has", gumjs_module_map_has },
  { "find", gumjs_module_map_find },
  { "findName", gumjs_module_map_find_name },
  { "findPath", gumjs_module_map_find_path },
  { "update", gumjs_module_map_update },
  { "values", gumjs_module_map_copy_values },

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

  auto map = _gum_v8_create_class ("ModuleMap", gumjs_module_map_construct,
      scope, module, isolate);
  _gum_v8_class_add (map, gumjs_module_map_functions, module, isolate);
}

void
_gum_v8_module_realize (GumV8Module * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  self->maps = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_module_map_free);

  auto type_key = _gum_v8_string_new_ascii (isolate, "type");
  self->type_key = new GumPersistent<String>::type (isolate, type_key);
  auto name_key = _gum_v8_string_new_ascii (isolate, "name");
  self->name_key = new GumPersistent<String>::type (isolate, name_key);
  auto module_key = _gum_v8_string_new_ascii (isolate, "module");
  self->module_key = new GumPersistent<String>::type (isolate, module_key);
  auto address_key = _gum_v8_string_new_ascii (isolate, "address");
  self->address_key = new GumPersistent<String>::type (isolate, address_key);
  auto slot_key = _gum_v8_string_new_ascii (isolate, "slot");
  self->slot_key = new GumPersistent<String>::type (isolate, slot_key);

  auto function_value = _gum_v8_string_new_ascii (isolate, "function");
  auto variable_value = _gum_v8_string_new_ascii (isolate, "variable");
  self->variable_value = new GumPersistent<String>::type (isolate,
      variable_value);

  auto empty_string = String::Empty (isolate);

  auto imp = Object::New (isolate);
  imp->Set (context, type_key, function_value).FromJust ();
  imp->Set (context, name_key, empty_string).FromJust ();
  imp->Set (context, module_key, empty_string).FromJust ();
  imp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->import_value = new GumPersistent<Object>::type (isolate, imp);

  auto exp = Object::New (isolate);
  exp->Set (context, type_key, function_value).FromJust ();
  exp->Set (context, name_key, empty_string).FromJust ();
  exp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->export_value = new GumPersistent<Object>::type (isolate, exp);
}

void
_gum_v8_module_dispose (GumV8Module * self)
{
  g_hash_table_unref (self->maps);
  self->maps = NULL;

  delete self->import_value;
  delete self->export_value;
  self->import_value = nullptr;
  self->export_value = nullptr;

  delete self->type_key;
  delete self->name_key;
  delete self->module_key;
  delete self->address_key;
  delete self->slot_key;
  delete self->variable_value;
  self->type_key = nullptr;
  self->name_key = nullptr;
  self->module_key = nullptr;
  self->address_key = nullptr;
  self->slot_key = nullptr;
  self->variable_value = nullptr;
}

void
_gum_v8_module_finalize (GumV8Module * self)
{
  (void) self;
}

/*
 * Prototype:
 * Module.ensureInitialized(name)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  auto success = gum_module_ensure_initialized (name);
  if (!success)
  {
    _gum_v8_throw (isolate, "unable to find module '%s'", name);
  }

  g_free (name);
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
  ic.slot = Local<String>::New (isolate, *module->slot_key);
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

  switch (details->type)
  {
    case GUM_IMPORT_FUNCTION:
    {
      /* the default value in our template */
      break;
    }
    case GUM_IMPORT_VARIABLE:
    {
      imp->Set (context, ic->type, ic->variable).FromJust ();
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

  imp->Set (context, ic->name,
      _gum_v8_string_new_ascii (isolate, details->name)).FromJust ();

  if (details->module != NULL)
  {
    imp->Set (context, ic->module,
        _gum_v8_string_new_ascii (isolate, details->module)).FromJust ();
  }
  else
  {
    imp->Delete (context, ic->module).FromJust ();
  }

  if (details->address != 0)
  {
    imp->Set (context, ic->address,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core))
        .FromJust ();
  }
  else
  {
    imp->Delete (context, ic->address).FromJust ();
  }

  if (details->slot != 0)
  {
    imp->Set (context, ic->slot,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->slot), core))
        .FromJust ();
  }
  else
  {
    imp->Delete (context, ic->slot).FromJust ();
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

  if (details->type != GUM_EXPORT_FUNCTION)
  {
    exp->Set (context, ec->type, ec->variable).FromJust ();
  }

  exp->Set (context, ec->name,
      _gum_v8_string_new_ascii (isolate, details->name)).FromJust ();

  exp->Set (context, ec->address,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core))
      .FromJust ();

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
 * Module.enumerateSymbols(name, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  gchar * name;
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }

  g_free (name);
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto symbol = Object::New (isolate);
  _gum_v8_object_set (symbol, "isGlobal",
      Boolean::New (isolate, details->is_global), core);
  _gum_v8_object_set_ascii (symbol, "type",
      gum_symbol_type_to_string (details->type), core);

  auto s = details->section;
  if (s != NULL)
  {
    auto section = Object::New (isolate);
    _gum_v8_object_set_ascii (section, "id", s->id, core);
    _gum_v8_object_set_page_protection (section, "protection", s->prot, core);
    _gum_v8_object_set (symbol, "section", section, core);
  }

  _gum_v8_object_set_ascii (symbol, "name", details->name, core);
  _gum_v8_object_set_pointer (symbol, "address", details->address, core);

  Handle<Value> argv[] = { symbol };
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
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }

  g_free (name);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->prot, core);

  Handle<Value> argv[] = { range };
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

  GumAddress address;

  core->isolate->Exit ();
  {
    Unlocker ul (core->isolate);

    address = gum_module_find_export_by_name (module_name, symbol_name);
  }
  core->isolate->Enter ();

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

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }

  Local<Function> filter_callback;
  if (!_gum_v8_args_parse (args, "|F", &filter_callback))
    return;

  GumModuleMap * handle;
  if (filter_callback.IsEmpty ())
  {
    handle = gum_module_map_new ();
  }
  else
  {
    GumV8ModuleFilter * filter;

    filter = g_slice_new (GumV8ModuleFilter);
    filter->callback =
        new GumPersistent<Function>::type (isolate, filter_callback);
    filter->core = core;

    handle = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_v8_module_filter_matches,
        filter, (GDestroyNotify) gum_v8_module_filter_free);
  }

  auto map = gum_v8_module_map_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, map);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_has, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));

  info.GetReturnValue ().Set (details != NULL);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_parse_module_details (details, core));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find_name, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->name));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find_path, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->path));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_update, GumV8ModuleMap)
{
  gum_module_map_update (self->handle);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_copy_values, GumV8ModuleMap)
{
  auto values = gum_module_map_get_values (self->handle);
  auto result = Array::New (isolate, values->len);

  for (guint i = 0; i != values->len; i++)
  {
    auto details = &g_array_index (values, GumModuleDetails, i);
    auto m = Object::New (isolate);
    _gum_v8_object_set_ascii (m, "name", details->name, core);
    _gum_v8_object_set_pointer (m, "base", details->range->base_address, core);
    _gum_v8_object_set_uint (m, "size", details->range->size, core);
    _gum_v8_object_set_utf8 (m, "path", details->path, core);
    result->Set (i, m);
  }

  info.GetReturnValue ().Set (result);
}

static GumV8ModuleMap *
gum_v8_module_map_new (Handle<Object> wrapper,
                       GumModuleMap * handle,
                       GumV8Module * module)
{
  auto map = g_slice_new (GumV8ModuleMap);
  map->wrapper =
      new GumPersistent<Object>::type (module->core->isolate, wrapper);
  map->wrapper->MarkIndependent ();
  map->wrapper->SetWeak (map, gum_v8_module_map_on_weak_notify,
      WeakCallbackType::kParameter);
  map->handle = handle;
  map->module = module;

  g_hash_table_add (module->maps, map);

  return map;
}

static void
gum_v8_module_map_free (GumV8ModuleMap * map)
{
  g_object_unref (map->handle);

  delete map->wrapper;

  g_slice_free (GumV8ModuleMap, map);
}

static void
gum_v8_module_map_on_weak_notify (const WeakCallbackInfo<GumV8ModuleMap> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->maps, self);
}

static void
gum_v8_module_filter_free (GumV8ModuleFilter * filter)
{
  delete filter->callback;

  g_slice_free (GumV8ModuleFilter, filter);
}

static gboolean
gum_v8_module_filter_matches (const GumModuleDetails * details,
                              GumV8ModuleFilter * self)
{
  auto core = self->core;
  Isolate * isolate = core->isolate;

  auto module = _gum_v8_parse_module_details (details, core);

  auto callback (Local<Function>::New (isolate, *self->callback));
  Handle<Value> argv[] = { module };

  auto result = callback->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  if (result.IsEmpty ())
  {
    core->current_scope->ProcessAnyPendingException ();
    return FALSE;
  }

  return result->IsBoolean () && result.As<Boolean> ()->Value ();
}
