/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

  GumQuickScope * scope;
};

struct _GumQuickModuleFilter
{
  JSValue callback;

  GumQuickModule * module;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_module_load)
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
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

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
static gboolean gum_quick_module_filter_matches (
    const GumModuleDetails * details, GumQuickModuleFilter * self);

static const JSClassDef gumjs_module_def =
{
  .class_name = "Module",
};

static const JSCFunctionListEntry gumjs_module_entries[] =
{
  GUMJS_EXPOSE_CFUNC ("_load", 0, gumjs_module_load),
  GUMJS_EXPORT_CFUNC ("ensureInitialized", 0, gumjs_module_ensure_initialized),
  GUMJS_EXPOSE_CFUNC ("_enumerateImports", 0, gumjs_module_enumerate_imports),
  GUMJS_EXPOSE_CFUNC ("_enumerateExports", 0, gumjs_module_enumerate_exports),
  GUMJS_EXPOSE_CFUNC ("_enumerateSymbols", 0, gumjs_module_enumerate_symbols),
  GUMJS_EXPOSE_CFUNC ("_enumerateRanges", 0, gumjs_module_enumerate_ranges),
  GUMJS_EXPORT_CFUNC ("findBaseAddress", 0, gumjs_module_find_base_address),
  GUMJS_EXPORT_CFUNC ("findExportByName", 0, gumjs_module_find_export_by_name),
};

static const JSClassDef gumjs_module_map_def =
{
  .class_name = "ModuleMap",
  .finalizer = gumjs_module_map_finalize,
};

static const JSCFunctionListEntry gumjs_module_map_entries[] =
{
  GUMJS_EXPORT_CGETSET ("handle", gumjs_module_map_get_handle, NULL),
  GUMJS_EXPORT_CFUNC ("has", 0, gumjs_module_map_has),
  GUMJS_EXPORT_CFUNC ("find", 0, gumjs_module_map_find),
  GUMJS_EXPORT_CFUNC ("findName", 0, gumjs_module_map_find_name),
  GUMJS_EXPORT_CFUNC ("findPath", 0, gumjs_module_map_find_path),
  GUMJS_EXPORT_CFUNC ("update", 0, gumjs_module_map_update),
  GUMJS_EXPORT_CFUNC ("values", 0, gumjs_module_map_copy_values),
};

void
_gum_quick_module_init (GumQuickModule * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSRuntime * rt = core->rt;
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "module", self);

  JS_NewClassID (&self->module_class);
  JS_NewClass (rt, self->module_class, &gumjs_module_def);
  proto = JS_NewObject (ctx);
  ctor = JS_NewCFunction2 (ctx, gumjs_module_construct,
      gumjs_module_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_module_entries,
      G_N_ELEMENTS (gumjs_module_entries));
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->module_class, proto);
  JS_DefinePropertyValueStr (ctx, ns, gumjs_module_def.class_name, ctor,
      JS_PROP_C_W_E);

  JS_NewClassID (&self->module_map_class);
  JS_NewClass (rt, self->module_map_class, &gumjs_module_map_def);
  proto = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_module_map_entries,
      G_N_ELEMENTS (gumjs_module_map_entries));
  ctor = JS_NewCFunction2 (ctx, gumjs_module_map_construct,
      gumjs_module_map_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetClassProto (ctx, self->module_map_class, proto);
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
_gum_quick_module_new (JSContext * ctx,
                       const GumModuleDetails * details,
                       GumQuickModule * module)
{
  GumQuickCore * core = module->core;
  JSValue m;

  m = JS_NewObjectClass (ctx, module->module_class);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_native_pointer_new (ctx,
          GSIZE_TO_POINTER (details->range->base_address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt32 (ctx, details->range->size),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, path),
      JS_NewString (ctx, details->path),
      JS_PROP_C_W_E);

  return m;
}

static GumQuickModule *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "module");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GError * error;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  error = NULL;
  gum_module_load (name, &error);

  _gum_quick_scope_resume (&scope);

  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean success;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  success = gum_module_ensure_initialized (name);

  _gum_quick_scope_resume (&scope);

  if (!success)
    return _gum_quick_throw (ctx, "unable to find module '%s'", name);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumQuickMatchContext mc;
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.scope = &scope;

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &mc);

  return JS_Call (ctx, mc.on_complete, JS_UNDEFINED, 0, NULL);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);

  quick_push_object (ctx);

  if (details->type != GUM_IMPORT_UNKNOWN)
  {
    quick_push_string (ctx,
        (details->type == GUM_IMPORT_FUNCTION) ? "function" : "variable");
    quick_put_prop_string (ctx, -2, "type");
  }

  quick_push_string (ctx, details->name);
  quick_put_prop_string (ctx, -2, "name");

  if (details->module != NULL)
  {
    quick_push_string (ctx, details->module);
    quick_put_prop_string (ctx, -2, "module");
  }

  if (details->address != 0)
  {
    _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
        scope->core);
    quick_put_prop_string (ctx, -2, "address");
  }

  if (details->slot != 0)
  {
    _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (details->slot),
        scope->core);
    quick_put_prop_string (ctx, -2, "slot");
  }

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumQuickMatchContext mc;
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  _gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);

  quick_push_object (ctx);

  quick_push_string (ctx,
      (details->type == GUM_EXPORT_FUNCTION) ? "function" : "variable");
  quick_put_prop_string (ctx, -2, "type");

  quick_push_string (ctx, details->name);
  quick_put_prop_string (ctx, -2, "name");

  _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
      scope->core);
  quick_put_prop_string (ctx, -2, "address");

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  GumQuickMatchContext mc;
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  _gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumQuickMatchContext * mc)
{
  const GumSymbolSection * section = details->section;
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);

  quick_push_object (ctx);

  quick_push_boolean (ctx, details->is_global);
  quick_put_prop_string (ctx, -2, "isGlobal");

  quick_push_string (ctx, gum_symbol_type_to_string (details->type));
  quick_put_prop_string (ctx, -2, "type");

  if (section != NULL)
  {
    quick_push_object (ctx);

    quick_push_string (ctx, section->id);
    quick_put_prop_string (ctx, -2, "id");

    _gum_quick_push_page_protection (ctx, section->prot);
    quick_put_prop_string (ctx, -2, "protection");

    quick_put_prop_string (ctx, -2, "section");
  }

  quick_push_string (ctx, details->name);
  quick_put_prop_string (ctx, -2, "name");

  _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
      scope->core);
  quick_put_prop_string (ctx, -2, "address");

  if (details->size != -1)
  {
    quick_push_uint (ctx, details->size);
    quick_put_prop_string (ctx, -2, "size");
  }

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumQuickMatchContext mc;
  gchar * name;
  GumPageProtection prot;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  _gum_quick_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);
  _gum_quick_push_range_details (ctx, details, scope->core);

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  const gchar * name;
  GumAddress address;

  _gum_quick_args_parse (args, "s", &name);

  address = gum_module_find_base_address (name);

  if (address != 0)
    _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (address),
        core);
  else
    quick_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  const gchar * module_name, * symbol_name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumAddress address;

  _gum_quick_args_parse (args, "s?s", &module_name, &symbol_name);

  _gum_quick_scope_suspend (&scope);
  address = gum_module_find_export_by_name (module_name, symbol_name);
  _gum_quick_scope_resume (&scope);

  if (address != 0)
    _gum_quick_push_native_pointer (ctx, GSIZE_TO_POINTER (address),
        core);
  else
    quick_push_null (ctx);
  return 1;
}

static GumModuleMap *
gumjs_module_map_from_args (const GumQuickArgs * args)
{
  JSContext * ctx = args->ctx;
  GumModuleMap * self;

  quick_push_this (ctx);
  self = _gum_quick_require_data (ctx, -1);
  if (self == NULL)
    _gum_quick_throw (ctx, "invalid operation");
  quick_pop (ctx);

  return self;
}

static gboolean
gum_quick_module_map_get (JSContext * ctx,
                          JSValueConst val,
                          GumQuickModule * parent,
                          GumModuleMap ** module_map)
{
  *module_map = JS_GetOpaque2 (ctx, val, parent->module_map_class);
  return *module_map != NULL;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  JSValue obj = JS_NULL;
  JSValue filter_callback;
  JSValue proto;
  GumModuleMap * map;

  if (JS_IsUndefined (new_target))
    goto missing_target;

  filter_callback = JS_NULL;
  if (!_gum_quick_args_parse (args, "|F", &filter_callback))
    goto propagate_exception;

  proto = JS_GetPropertyStr (ctx, new_target, "prototype");
  obj = JS_NewObjectProtoClass (ctx, proto, parent->module_map_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (obj))
    goto propagate_exception;

  if (JS_IsNull (filter_callback))
  {
    map = gum_module_map_new ();
  }
  else
  {
    GumQuickModuleFilter * filter;

    filter = g_slice_new (GumQuickModuleFilter);
    _gum_quick_protect (ctx, filter_callback);
    filter->callback = JS_DupValue (ctx, filter_callback);
    filter->module = gumjs_module_from_args (args);

    map = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_quick_module_filter_matches,
        filter, (GDestroyNotify) gum_quick_module_filter_free);
  }

  JS_SetOpaque (obj, map);

  return obj;

missing_target:
  {
    _gum_quick_throw_literal (ctx,
        "use `new ModuleMap()` to create a new instance");
    goto propagate_exception;
  }
propagate_exception:
  {
    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_module_map_finalize)
{
  GumModuleMap * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_object_unref (self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_module_map_get_handle)
{
  return _gum_quick_native_pointer_new (ctx, gum_quick_module_map_get (ctx),
      core);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_has)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_quick_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));

  quick_push_boolean (ctx, details != NULL);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_quick_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    quick_push_null (ctx);
    return 1;
  }

  _gum_quick_push_module (ctx, details, gumjs_module_from_args (args));
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_name)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_quick_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    quick_push_null (ctx);
    return 1;
  }

  quick_push_string (ctx, details->name);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_path)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_quick_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    quick_push_null (ctx);
    return 1;
  }

  quick_push_string (ctx, details->path);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_update)
{
  gum_module_map_update (gumjs_module_map_from_args (args));
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_copy_values)
{
  GumModuleMap * self;
  GumQuickModule * module;
  const GArray * values;
  guint i;

  self = gumjs_module_map_from_args (args);
  module = gumjs_module_from_args (args);
  values = gum_module_map_get_values (self);

  quick_push_array (ctx);
  for (i = 0; i != values->len; i++)
  {
    GumModuleDetails * details;

    details = &g_array_index (values, GumModuleDetails, i);
    _gum_quick_push_module (ctx, details, module);
    quick_put_prop_index (ctx, -2, i);
  }

  return 1;
}

static void
gum_quick_module_filter_free (GumQuickModuleFilter * filter)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (filter->module->core);

  _gum_quick_unprotect (scope.ctx, filter->callback);

  g_slice_free (GumQuickModuleFilter, filter);
}

static gboolean
gum_quick_module_filter_matches (const GumModuleDetails * details,
                               GumQuickModuleFilter * self)
{
  GumQuickModule * module = self->module;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (module->core);
  JSContext * ctx = scope.ctx;
  gboolean result = FALSE;

  quick_push_heapptr (ctx, self->callback);
  _gum_quick_push_module (ctx, details, module);
  if (_gum_quick_scope_call (&scope, 1))
  {
    result = quick_is_boolean (ctx, -1) && quick_require_boolean (ctx, -1);
  }
  quick_pop (ctx);

  return result;
}
