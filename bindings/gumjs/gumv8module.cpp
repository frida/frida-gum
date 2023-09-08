/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8module.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"

#include <gum/gum-init.h>
#include <string.h>

#define GUMJS_MODULE_NAME Module

using namespace v8;

class GumV8ImportsContext : public GumV8MatchContext<GumV8Module>
{
public:
  GumV8ImportsContext (Isolate * isolate, GumV8Module * parent)
    : GumV8MatchContext (isolate, parent)
  {
  }

  Local<Object> imp;
  Local<String> type;
  Local<String> name;
  Local<String> module;
  Local<String> address;
  Local<String> slot;
  Local<String> variable;
};

struct GumV8ExportsContext : public GumV8MatchContext<GumV8Module>
{
public:
  GumV8ExportsContext (Isolate * isolate, GumV8Module * parent)
    : GumV8MatchContext (isolate, parent)
  {
  }

  Local<Object> exp;
  Local<String> type;
  Local<String> name;
  Local<String> address;
  Local<String> variable;
};

struct GumV8ModuleMap
{
  Global<Object> * wrapper;
  GumModuleMap * handle;

  GumV8Module * module;
};

struct GumV8ModuleFilter
{
  Global<Function> * callback;

  GumV8Module * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_load)
GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumV8ImportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumV8ExportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_sections)
static gboolean gum_emit_section (const GumSectionDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_map_construct)
GUMJS_DECLARE_GETTER (gumjs_module_map_get_handle)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_has)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_path)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_update)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_copy_values)

static GumV8ModuleMap * gum_v8_module_map_new (Local<Object> wrapper,
    GumModuleMap * handle, GumV8Module * module);
static void gum_v8_module_map_free (GumV8ModuleMap * self);
static void gum_v8_module_map_on_weak_notify (
    const WeakCallbackInfo<GumV8ModuleMap> & info);

static void gum_v8_module_filter_free (GumV8ModuleFilter * filter);
static gboolean gum_v8_module_filter_matches (const GumModuleDetails * details,
    GumV8ModuleFilter * self);

static const GumV8Function gumjs_module_static_functions[] =
{
  { "_load", gumjs_module_load },
  { "ensureInitialized", gumjs_module_ensure_initialized },
  { "_enumerateImports", gumjs_module_enumerate_imports },
  { "_enumerateExports", gumjs_module_enumerate_exports },
  { "_enumerateSymbols", gumjs_module_enumerate_symbols },
  { "_enumerateRanges", gumjs_module_enumerate_ranges },
  { "_enumerateSections", gumjs_module_enumerate_sections },
  { "findBaseAddress", gumjs_module_find_base_address },
  { "findExportByName", gumjs_module_find_export_by_name },

  { NULL, NULL }
};

static const GumV8Property gumjs_module_map_values[] =
{
  { "handle", gumjs_module_map_get_handle, NULL },

  { NULL, NULL, NULL }
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
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto klass = _gum_v8_create_class ("Module", nullptr, scope, module, isolate);
  _gum_v8_class_add_static (klass, gumjs_module_static_functions, module,
      isolate);
  self->klass = new Global<FunctionTemplate> (isolate, klass);

  auto map = _gum_v8_create_class ("ModuleMap", gumjs_module_map_construct,
      scope, module, isolate);
  _gum_v8_class_add (map, gumjs_module_map_values, module, isolate);
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
  self->type_key = new Global<String> (isolate, type_key);
  auto name_key = _gum_v8_string_new_ascii (isolate, "name");
  self->name_key = new Global<String> (isolate, name_key);
  auto module_key = _gum_v8_string_new_ascii (isolate, "module");
  self->module_key = new Global<String> (isolate, module_key);
  auto address_key = _gum_v8_string_new_ascii (isolate, "address");
  self->address_key = new Global<String> (isolate, address_key);
  auto slot_key = _gum_v8_string_new_ascii (isolate, "slot");
  self->slot_key = new Global<String> (isolate, slot_key);

  auto function_value = _gum_v8_string_new_ascii (isolate, "function");
  auto variable_value = _gum_v8_string_new_ascii (isolate, "variable");
  self->variable_value = new Global<String> (isolate, variable_value);

  auto empty_string = String::Empty (isolate);

  auto imp = Object::New (isolate);
  imp->Set (context, type_key, function_value).FromJust ();
  imp->Set (context, name_key, empty_string).FromJust ();
  imp->Set (context, module_key, empty_string).FromJust ();
  imp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->import_value = new Global<Object> (isolate, imp);

  auto exp = Object::New (isolate);
  exp->Set (context, type_key, function_value).FromJust ();
  exp->Set (context, name_key, empty_string).FromJust ();
  exp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->export_value = new Global<Object> (isolate, exp);
}

void
_gum_v8_module_dispose (GumV8Module * self)
{
  g_hash_table_unref (self->maps);
  self->maps = NULL;

  delete self->klass;
  self->klass = nullptr;

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
}

Local<Object>
_gum_v8_module_value_new (const GumModuleDetails * details,
                          GumV8Module * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto klass = Local<FunctionTemplate>::New (isolate, *module->klass);
  auto value = klass->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  _gum_v8_object_set_utf8 (value, "name", details->name, core);
  _gum_v8_object_set_pointer (value, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (value, "size", details->range->size, core);
  _gum_v8_object_set_utf8 (value, "path", details->path, core);
  return value;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  GError * error;
  {
    ScriptUnlocker unlocker (core);

    error = NULL;
    gum_module_load (name, &error);
  }

  _gum_v8_maybe_throw (isolate, &error);

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  gboolean success;
  {
    ScriptUnlocker unlocker (core);

    success = gum_module_ensure_initialized (name);
  }

  if (!success)
  {
    _gum_v8_throw (isolate, "unable to find module '%s'", name);
  }

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  gchar * name;
  GumV8ImportsContext ic (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ic.on_match,
      &ic.on_complete))
    return;

  ic.imp = Local<Object>::New (isolate, *module->import_value);
  ic.type = Local<String>::New (isolate, *module->type_key);
  ic.name = Local<String>::New (isolate, *module->name_key);
  ic.module = Local<String>::New (isolate, *module->module_key);
  ic.address = Local<String>::New (isolate, *module->address_key);
  ic.slot = Local<String>::New (isolate, *module->slot_key);
  ic.variable = Local<String>::New (isolate, *module->variable_value);

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &ic);

  ic.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumV8ImportsContext * ic)
{
  auto core = ic->parent->core;
  auto isolate = ic->isolate;
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

  return ic->OnMatch (imp);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  gchar * name;
  GumV8ExportsContext ec (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ec.on_match,
      &ec.on_complete))
    return;

  ec.exp = Local<Object>::New (isolate, *module->export_value);
  ec.type = Local<String>::New (isolate, *module->type_key);
  ec.name = Local<String>::New (isolate, *module->name_key);
  ec.address = Local<String>::New (isolate, *module->address_key);
  ec.variable = Local<String>::New (isolate, *module->variable_value);

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &ec);

  ec.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumV8ExportsContext * ec)
{
  auto core = ec->parent->core;
  auto isolate = ec->isolate;
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

  return ec->OnMatch (exp);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  gchar * name;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
    return;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

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
    _gum_v8_object_set_page_protection (section, "protection", s->protection,
        core);
    _gum_v8_object_set (symbol, "section", section, core);
  }

  _gum_v8_object_set_ascii (symbol, "name", details->name, core);
  _gum_v8_object_set_pointer (symbol, "address", details->address, core);
  if (details->size != -1)
    _gum_v8_object_set_uint (symbol, "size", details->size, core);

  return mc->OnMatch (symbol);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  gchar * name;
  GumPageProtection prot;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
    return;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_sections)
{
  gchar * name;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return;

  gum_module_enumerate_sections (name, (GumFoundSectionFunc) gum_emit_section,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_section (const GumSectionDetails * details,
                  GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto section = Object::New (isolate);
  _gum_v8_object_set_utf8 (section, "id", details->id, core);
  _gum_v8_object_set_utf8 (section, "name", details->name, core);
  _gum_v8_object_set_pointer (section, "address", details->address, core);
  _gum_v8_object_set_uint (section, "size", details->size, core);

  return mc->OnMatch (section);
}

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

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  gchar * module_name, * symbol_name;
  if (!_gum_v8_args_parse (args, "s?s", &module_name, &symbol_name))
    return;

  GumAddress address;
  {
    ScriptUnlocker unlocker (core);

    address = gum_module_find_export_by_name (module_name, symbol_name);
  }

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
    filter->callback = new Global<Function> (isolate, filter_callback);
    filter->module = module;

    handle = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_v8_module_filter_matches,
        filter, (GDestroyNotify) gum_v8_module_filter_free);
  }

  auto map = gum_v8_module_map_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, map);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_module_map_get_handle, GumV8ModuleMap)
{
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (self->handle, core));
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

  info.GetReturnValue ().Set (_gum_v8_module_value_new (details, module));
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

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->name)
      .ToLocalChecked ());
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

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->path)
      .ToLocalChecked ());
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_update, GumV8ModuleMap)
{
  gum_module_map_update (self->handle);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_copy_values, GumV8ModuleMap)
{
  auto context = isolate->GetCurrentContext ();

  auto values = gum_module_map_get_values (self->handle);
  auto result = Array::New (isolate, values->len);

  for (guint i = 0; i != values->len; i++)
  {
    auto details = &g_array_index (values, GumModuleDetails, i);
    auto m = _gum_v8_module_value_new (details, module);
    result->Set (context, i, m).Check ();
  }

  info.GetReturnValue ().Set (result);
}

static GumV8ModuleMap *
gum_v8_module_map_new (Local<Object> wrapper,
                       GumModuleMap * handle,
                       GumV8Module * module)
{
  auto map = g_slice_new (GumV8ModuleMap);
  map->wrapper = new Global<Object> (module->core->isolate, wrapper);
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
  auto core = self->module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto module = _gum_v8_module_value_new (details, self->module);

  auto callback (Local<Function>::New (isolate, *self->callback));
  auto recv = Undefined (isolate);
  Local<Value> argv[] = { module };
  Local<Value> result;
  if (callback->Call (context, recv, G_N_ELEMENTS (argv), argv)
      .ToLocal (&result))
  {
    return result->IsBoolean () && result.As<Boolean> ()->Value ();
  }
  else
  {
    core->current_scope->ProcessAnyPendingException ();
    return FALSE;
  }
}
