/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickmodule.h"

#include "gumquickmacros.h"

typedef struct _GumQuickMatchContext GumQuickMatchContext;
typedef struct _GumQuickModuleFilter GumQuickModuleFilter;

struct _GumQuickMatchContext
{
  JSValue on_match;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumQuickModuleFilter
{
  JSValue callback;

  GumQuickModule * parent;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_load)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_global_export_by_name)
GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
GUMJS_DECLARE_FINALIZER (gumjs_module_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_get_name)
GUMJS_DECLARE_GETTER (gumjs_module_get_path)
GUMJS_DECLARE_GETTER (gumjs_module_get_base)
GUMJS_DECLARE_GETTER (gumjs_module_get_size)
GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_sections)
static gboolean gum_emit_section (const GumSectionDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_dependencies)
static gboolean gum_emit_dependency (const GumDependencyDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_symbol_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_map_construct)
GUMJS_DECLARE_FINALIZER (gumjs_module_map_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_map_get_handle)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_has)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_path)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_update)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_copy_values)

static void gum_quick_module_filter_free (GumQuickModuleFilter * filter);
static gboolean gum_quick_module_filter_matches (GumModule * module,
    GumQuickModuleFilter * self);

static const JSClassDef gumjs_module_def =
{
  .class_name = "Module",
  .finalizer = gumjs_module_finalize,
};

static const JSCFunctionListEntry gumjs_module_static_entries[] =
{
  JS_CFUNC_DEF ("load", 0, gumjs_module_load),
  JS_CFUNC_DEF ("findGlobalExportByName", 0,
      gumjs_module_find_global_export_by_name),
};

static const JSCFunctionListEntry gumjs_module_entries[] =
{
  JS_CGETSET_DEF ("name", gumjs_module_get_name, NULL),
  JS_CGETSET_DEF ("path", gumjs_module_get_path, NULL),
  JS_CGETSET_DEF ("base", gumjs_module_get_base, NULL),
  JS_CGETSET_DEF ("size", gumjs_module_get_size, NULL),
  JS_CFUNC_DEF ("ensureInitialized", 0, gumjs_module_ensure_initialized),
  JS_CFUNC_DEF ("_enumerateImports", 0, gumjs_module_enumerate_imports),
  JS_CFUNC_DEF ("_enumerateExports", 0, gumjs_module_enumerate_exports),
  JS_CFUNC_DEF ("_enumerateSymbols", 0, gumjs_module_enumerate_symbols),
  JS_CFUNC_DEF ("_enumerateRanges", 0, gumjs_module_enumerate_ranges),
  JS_CFUNC_DEF ("_enumerateSections", 0, gumjs_module_enumerate_sections),
  JS_CFUNC_DEF ("_enumerateDependencies", 0,
      gumjs_module_enumerate_dependencies),
  JS_CFUNC_DEF ("findExportByName", 0, gumjs_module_find_export_by_name),
  JS_CFUNC_DEF ("findSymbolByName", 0, gumjs_module_find_symbol_by_name),
};

static const JSClassDef gumjs_module_map_def =
{
  .class_name = "ModuleMap",
  .finalizer = gumjs_module_map_finalize,
};

static const JSCFunctionListEntry gumjs_module_map_entries[] =
{
  JS_CGETSET_DEF ("handle", gumjs_module_map_get_handle, NULL),
  JS_CFUNC_DEF ("has", 0, gumjs_module_map_has),
  JS_CFUNC_DEF ("find", 0, gumjs_module_map_find),
  JS_CFUNC_DEF ("findName", 0, gumjs_module_map_find_name),
  JS_CFUNC_DEF ("findPath", 0, gumjs_module_map_find_path),
  JS_CFUNC_DEF ("update", 0, gumjs_module_map_update),
  JS_CFUNC_DEF ("values", 0, gumjs_module_map_copy_values),
};

void
_gum_quick_module_init (GumQuickModule * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "module", self);

  _gum_quick_create_class (ctx, &gumjs_module_def, core, &self->module_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_module_construct,
      gumjs_module_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_module_static_entries,
      G_N_ELEMENTS (gumjs_module_static_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_module_entries,
      G_N_ELEMENTS (gumjs_module_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_module_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_module_map_def, core,
      &self->module_map_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_module_map_construct,
      gumjs_module_map_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_module_map_entries,
      G_N_ELEMENTS (gumjs_module_map_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_module_map_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_module_dispose (GumQuickModule * self)
{
}

void
_gum_quick_module_finalize (GumQuickModule * self)
{
}

JSValue
_gum_quick_module_new_from_handle (JSContext * ctx,
                                   GumModule * module,
                                   GumQuickModule * parent)
{
  return _gum_quick_module_new_take_handle (ctx, g_object_ref (module), parent);
}

JSValue
_gum_quick_module_new_take_handle (JSContext * ctx,
                                   GumModule * module,
                                   GumQuickModule * parent)
{
  JSValue wrapper = JS_NewObjectClass (ctx, parent->module_class);

  JS_SetOpaque (wrapper, module);

  return wrapper;
}

static GumQuickModule *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "module");
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  GumModule * module;
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GError * error;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  error = NULL;
  module = gum_module_load (name, &error);

  _gum_quick_scope_resume (&scope);

  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return _gum_quick_module_new_take_handle (ctx, module,
      gumjs_get_parent_module (core));
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_global_export_by_name)
{
  const gchar * symbol_name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumAddress address;

  if (!_gum_quick_args_parse (args, "s", &symbol_name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  address = gum_module_find_global_export_by_name (symbol_name);

  _gum_quick_scope_resume (&scope);

  if (address == 0)
    return JS_NULL;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
}

static gboolean
gum_module_entry_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      GumModule ** module)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->module_class, core, (gpointer *) module);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FINALIZER (gumjs_module_finalize)
{
  GumModule * m;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  m = JS_GetOpaque (val, gumjs_get_parent_module (core)->module_class);
  if (m == NULL)
    return;

  _gum_quick_scope_suspend (&scope);

  g_object_unref (m);

  _gum_quick_scope_resume (&scope);
}

GUMJS_DEFINE_GETTER (gumjs_module_get_name)
{
  GumModule * self;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, gum_module_get_name (self));
}

GUMJS_DEFINE_GETTER (gumjs_module_get_path)
{
  GumModule * self;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, gum_module_get_path (self));
}

GUMJS_DEFINE_GETTER (gumjs_module_get_base)
{
  GumModule * self;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (gum_module_get_range (self)->base_address),
      core);
}

GUMJS_DEFINE_GETTER (gumjs_module_get_size)
{
  GumModule * self;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, gum_module_get_range (self)->size);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  GumModule * self;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  gum_module_ensure_initialized (self);

  _gum_quick_scope_resume (&scope);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumModule * self;
  GumQuickMatchContext mc;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
        &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_imports (self, (GumFoundImportFunc) gum_emit_import,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue imp, result;

  imp = JS_NewObject (ctx);

  if (details->type != GUM_IMPORT_UNKNOWN)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, (details->type == GUM_IMPORT_FUNCTION)
            ? "function" : "variable"),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, imp,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  if (details->module != NULL)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, module),
        JS_NewString (ctx, details->module),
        JS_PROP_C_W_E);
  }
  if (details->address != 0)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, address),
        _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
            core),
        JS_PROP_C_W_E);
  }
  if (details->slot != 0)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, slot),
        _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->slot),
            core),
        JS_PROP_C_W_E);
  }

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &imp);

  JS_FreeValue (ctx, imp);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumModule * self;
  GumQuickMatchContext mc;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
        &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_exports (self, (GumFoundExportFunc) gum_emit_export,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue exp, result;

  exp = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, (details->type == GUM_EXPORT_FUNCTION)
          ? "function" : "variable"),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &exp);

  JS_FreeValue (ctx, exp);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  GumModule * self;
  GumQuickMatchContext mc;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
        &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_symbols (self, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumQuickMatchContext * mc)
{
  const GumSymbolSection * section = details->section;
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue sym, result;

  sym = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, isGlobal),
      JS_NewBool (ctx, details->is_global),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, gum_symbol_type_to_string (details->type)),
      JS_PROP_C_W_E);
  if (section != NULL)
  {
    JSValue sect = JS_NewObject (ctx);

    JS_DefinePropertyValue (ctx, sect,
        GUM_QUICK_CORE_ATOM (core, id),
        JS_NewString (ctx, section->id),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, sect,
        GUM_QUICK_CORE_ATOM (core, protection),
        _gum_quick_page_protection_new (ctx, section->protection),
        JS_PROP_C_W_E);

    JS_DefinePropertyValue (ctx, sym,
        GUM_QUICK_CORE_ATOM (core, section),
        sect,
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);
  if (details->size != -1)
  {
    JS_DefinePropertyValue (ctx, sym,
        GUM_QUICK_CORE_ATOM (core, size),
        JS_NewInt64 (ctx, details->size),
        JS_PROP_C_W_E);
  }

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &sym);

  JS_FreeValue (ctx, sym);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumModule * self;
  GumQuickMatchContext mc;
  GumPageProtection prot;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "mF{onMatch,onComplete}", &prot,
        &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_ranges (self, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue d, result;

  d = _gum_quick_range_details_new (ctx, details, core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &d);

  JS_FreeValue (ctx, d);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_sections)
{
  GumModule * self;
  GumQuickMatchContext mc;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
        &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_sections (self, (GumFoundSectionFunc) gum_emit_section,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_section (const GumSectionDetails * details,
                  GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue section, result;

  section = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, id),
      JS_NewString (ctx, details->id),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewUint32 (ctx, details->size),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &section);

  JS_FreeValue (ctx, section);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_dependencies)
{
  GumModule * self;
  GumQuickMatchContext mc;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
        &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_dependencies (self,
      (GumFoundDependencyFunc) gum_emit_dependency, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_dependency (const GumDependencyDetails * details,
                     GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue dep, result;

  dep = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, dep,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, dep,
      GUM_QUICK_CORE_ATOM (core, type),
      _gum_quick_enum_new (ctx, details->type, GUM_TYPE_DEPENDENCY_TYPE),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &dep);

  JS_FreeValue (ctx, dep);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  GumModule * self;
  const gchar * symbol_name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumAddress address;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "s", &symbol_name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  address = gum_module_find_export_by_name (self, symbol_name);

  _gum_quick_scope_resume (&scope);

  if (address == 0)
    return JS_NULL;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_symbol_by_name)
{
  GumModule * self;
  const gchar * symbol_name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumAddress address;

  if (!gum_module_entry_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "s", &symbol_name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  address = gum_module_find_symbol_by_name (self, symbol_name);

  _gum_quick_scope_resume (&scope);

  if (address == 0)
    return JS_NULL;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
}

static gboolean
gum_quick_module_map_get (JSContext * ctx,
                          JSValueConst val,
                          GumQuickCore * core,
                          GumModuleMap ** map)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->module_map_class, core,
      (gpointer *) map);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickModule * parent;
  JSValue filter_callback;
  JSValue proto;
  GumModuleMap * map;

  parent = gumjs_get_parent_module (core);

  filter_callback = JS_NULL;
  if (!_gum_quick_args_parse (args, "|F", &filter_callback))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->module_map_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  if (JS_IsNull (filter_callback))
  {
    map = gum_module_map_new ();
  }
  else
  {
    GumQuickModuleFilter * filter;

    filter = g_slice_new (GumQuickModuleFilter);
    filter->callback = filter_callback;
    filter->parent = parent;

    map = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_quick_module_filter_matches,
        filter, (GDestroyNotify) gum_quick_module_filter_free);

    JS_DefinePropertyValue (ctx, wrapper,
        GUM_QUICK_CORE_ATOM (core, resource),
        JS_DupValue (ctx, filter_callback),
        0);
  }

  JS_SetOpaque (wrapper, map);

  return wrapper;
}

GUMJS_DEFINE_FINALIZER (gumjs_module_map_finalize)
{
  GumModuleMap * m;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  m = JS_GetOpaque (val, gumjs_get_parent_module (core)->module_map_class);
  if (m == NULL)
    return;

  _gum_quick_scope_suspend (&scope);

  g_object_unref (m);

  _gum_quick_scope_resume (&scope);
}

GUMJS_DEFINE_GETTER (gumjs_module_map_get_handle)
{
  GumModuleMap * self;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, self, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_has)
{
  GumModuleMap * self;
  gpointer address;
  GumModule * module;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  module = gum_module_map_find (self, GUM_ADDRESS (address));

  return JS_NewBool (ctx, module != NULL);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find)
{
  GumModuleMap * self;
  gpointer address;
  GumModule * module;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  module = gum_module_map_find (self, GUM_ADDRESS (address));
  if (module == NULL)
    return JS_NULL;

  return _gum_quick_module_new_from_handle (ctx, module,
      gumjs_get_parent_module (core));
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_name)
{
  GumModuleMap * self;
  gpointer address;
  GumModule * module;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  module = gum_module_map_find (self, GUM_ADDRESS (address));
  if (module == NULL)
    return JS_NULL;

  return JS_NewString (ctx, gum_module_get_name (module));
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_path)
{
  GumModuleMap * self;
  gpointer address;
  GumModule * module;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  module = gum_module_map_find (self, GUM_ADDRESS (address));
  if (module == NULL)
    return JS_NULL;

  return JS_NewString (ctx, gum_module_get_path (module));
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_update)
{
  GumModuleMap * self;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  gum_module_map_update (self);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_copy_values)
{
  JSValue result;
  GumModuleMap * self;
  GumQuickModule * parent;
  const GPtrArray * values;
  guint i;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  parent = gumjs_get_parent_module (core);

  values = gum_module_map_get_values (self);

  result = JS_NewArray (ctx);
  for (i = 0; i != values->len; i++)
  {
    GumModule * m = g_ptr_array_index (values, i);
    JS_DefinePropertyValueUint32 (ctx, result, i,
        _gum_quick_module_new_from_handle (ctx, m, parent),
        JS_PROP_C_W_E);
  }

  return result;
}

static void
gum_quick_module_filter_free (GumQuickModuleFilter * filter)
{
  g_slice_free (GumQuickModuleFilter, filter);
}

static gboolean
gum_quick_module_filter_matches (GumModule * module,
                                 GumQuickModuleFilter * self)
{
  GumQuickModule * parent = self->parent;
  GumQuickCore * core = parent->core;
  JSContext * ctx = core->ctx;
  gboolean is_match;
  JSValue m, v;

  m = _gum_quick_module_new_from_handle (ctx, module, parent);

  v = _gum_quick_scope_call (core->current_scope, self->callback, JS_UNDEFINED,
      1, &m);

  is_match = JS_IsBool (v) && JS_VALUE_GET_BOOL (v);

  JS_FreeValue (ctx, v);
  JS_FreeValue (ctx, m);

  return is_match;
}
