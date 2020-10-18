/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukmodule.h"

#include "gumdukmacros.h"

typedef struct _GumDukMatchContext GumDukMatchContext;
typedef struct _GumDukModuleFilter GumDukModuleFilter;

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

struct _GumDukModuleFilter
{
  GumDukHeapPtr callback;

  GumDukModule * module;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_module_load)
GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumDukMatchContext * mc);
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

static void gum_duk_module_filter_free (GumDukModuleFilter * filter);
static gboolean gum_duk_module_filter_matches (const GumModuleDetails * details,
    GumDukModuleFilter * self);

static const duk_function_list_entry gumjs_module_functions[] =
{
  { "_load", gumjs_module_load, 1 },
  { "ensureInitialized", gumjs_module_ensure_initialized, 1 },
  { "_enumerateImports", gumjs_module_enumerate_imports, 2 },
  { "_enumerateExports", gumjs_module_enumerate_exports, 2 },
  { "_enumerateSymbols", gumjs_module_enumerate_symbols, 2 },
  { "_enumerateRanges", gumjs_module_enumerate_ranges, 3 },
  { "findBaseAddress", gumjs_module_find_base_address, 1 },
  { "findExportByName", gumjs_module_find_export_by_name, 2 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_module_map_values[] =
{
  { "handle", gumjs_module_map_get_handle, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_module_map_functions[] =
{
  { "has", gumjs_module_map_has, 1 },
  { "find", gumjs_module_map_find, 1 },
  { "findName", gumjs_module_map_find_name, 1 },
  { "findPath", gumjs_module_map_find_path, 1 },
  { "update", gumjs_module_map_update, 0 },
  { "values", gumjs_module_map_copy_values, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_module_init (GumDukModule * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "module", self);

  duk_push_c_function (ctx, gumjs_module_construct, 0);
  duk_push_object (ctx);
  duk_put_prop_string (ctx, -2, "prototype");
  self->klass = _gum_duk_require_heapptr (ctx, -1);
  duk_put_function_list (ctx, -1, gumjs_module_functions);
  duk_put_global_string (ctx, "Module");

  duk_push_c_function (ctx, gumjs_module_map_construct, 3);
  duk_push_object (ctx);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_module_map_values);
  duk_put_function_list (ctx, -1, gumjs_module_map_functions);
  duk_push_c_function (ctx, gumjs_module_map_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_put_global_string (ctx, "ModuleMap");
}

void
_gum_duk_module_dispose (GumDukModule * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->klass);
}

void
_gum_duk_module_finalize (GumDukModule * self)
{
}

void
_gum_duk_push_module (duk_context * ctx,
                      const GumModuleDetails * details,
                      GumDukModule * module)
{
  duk_push_heapptr (ctx, module->klass);
  duk_new (ctx, 0);

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_native_pointer (ctx,
      GSIZE_TO_POINTER (details->range->base_address), module->core);
  duk_put_prop_string (ctx, -2, "base");

  duk_push_uint (ctx, details->range->size);
  duk_put_prop_string (ctx, -2, "size");

  duk_push_string (ctx, details->path);
  duk_put_prop_string (ctx, -2, "path");
}

static GumDukModule *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "module");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  const gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);
  GError * error;

  _gum_duk_args_parse (args, "s", &name);

  _gum_duk_scope_suspend (&scope);
  error = NULL;
  gum_module_load (name, &error);
  _gum_duk_scope_resume (&scope);

  if (error != NULL)
    _gum_duk_throw_error (ctx, &error);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  const gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);
  gboolean success;

  _gum_duk_args_parse (args, "s", &name);

  _gum_duk_scope_suspend (&scope);
  success = gum_module_ensure_initialized (name);
  _gum_duk_scope_resume (&scope);

  if (!success)
  {
    _gum_duk_throw (ctx, "unable to find module '%s'", name);
  }

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumDukMatchContext mc;
  const gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  if (details->type != GUM_IMPORT_UNKNOWN)
  {
    duk_push_string (ctx,
        (details->type == GUM_IMPORT_FUNCTION) ? "function" : "variable");
    duk_put_prop_string (ctx, -2, "type");
  }

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  if (details->module != NULL)
  {
    duk_push_string (ctx, details->module);
    duk_put_prop_string (ctx, -2, "module");
  }

  if (details->address != 0)
  {
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
        scope->core);
    duk_put_prop_string (ctx, -2, "address");
  }

  if (details->slot != 0)
  {
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (details->slot),
        scope->core);
    duk_put_prop_string (ctx, -2, "slot");
  }

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumDukMatchContext mc;
  const gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  duk_push_string (ctx,
      (details->type == GUM_EXPORT_FUNCTION) ? "function" : "variable");
  duk_put_prop_string (ctx, -2, "type");

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
      scope->core);
  duk_put_prop_string (ctx, -2, "address");

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  GumDukMatchContext mc;
  const gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumDukMatchContext * mc)
{
  const GumSymbolSection * section = details->section;
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  duk_push_boolean (ctx, details->is_global);
  duk_put_prop_string (ctx, -2, "isGlobal");

  duk_push_string (ctx, gum_symbol_type_to_string (details->type));
  duk_put_prop_string (ctx, -2, "type");

  if (section != NULL)
  {
    duk_push_object (ctx);

    duk_push_string (ctx, section->id);
    duk_put_prop_string (ctx, -2, "id");

    _gum_duk_push_page_protection (ctx, section->prot);
    duk_put_prop_string (ctx, -2, "protection");

    duk_put_prop_string (ctx, -2, "section");
  }

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (details->address),
      scope->core);
  duk_put_prop_string (ctx, -2, "address");

  if (details->size != -1)
  {
    duk_push_uint (ctx, details->size);
    duk_put_prop_string (ctx, -2, "size");
  }

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumDukMatchContext mc;
  gchar * name;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete);
  mc.scope = &scope;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);
  _gum_duk_push_range_details (ctx, details, scope->core);

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  const gchar * name;
  GumAddress address;

  _gum_duk_args_parse (args, "s", &name);

  address = gum_module_find_base_address (name);

  if (address != 0)
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (address), args->core);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  const gchar * module_name, * symbol_name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);
  GumAddress address;

  _gum_duk_args_parse (args, "s?s", &module_name, &symbol_name);

  _gum_duk_scope_suspend (&scope);
  address = gum_module_find_export_by_name (module_name, symbol_name);
  _gum_duk_scope_resume (&scope);

  if (address != 0)
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (address), args->core);
  else
    duk_push_null (ctx);
  return 1;
}

static GumModuleMap *
gumjs_module_map_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumModuleMap * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  if (self == NULL)
    _gum_duk_throw (ctx, "invalid operation");
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  GumDukHeapPtr filter_callback;
  GumModuleMap * module_map;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

  filter_callback = NULL;
  _gum_duk_args_parse (args, "|F", &filter_callback);

  if (filter_callback == NULL)
  {
    module_map = gum_module_map_new ();
  }
  else
  {
    GumDukModuleFilter * filter;

    filter = g_slice_new (GumDukModuleFilter);
    _gum_duk_protect (ctx, filter_callback);
    filter->callback = filter_callback;
    filter->module = gumjs_module_from_args (args);

    module_map = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_duk_module_filter_matches,
        filter, (GDestroyNotify) gum_duk_module_filter_free);
  }

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, module_map);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_module_map_finalize)
{
  GumModuleMap * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_object_unref (self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_module_map_get_handle)
{
  _gum_duk_push_native_pointer (ctx, gumjs_module_map_from_args (args),
      args->core);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_has)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_duk_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));

  duk_push_boolean (ctx, details != NULL);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_duk_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  _gum_duk_push_module (ctx, details, gumjs_module_from_args (args));
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_name)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_duk_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_string (ctx, details->name);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_path)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  self = gumjs_module_map_from_args (args);

  _gum_duk_args_parse (args, "p", &address);

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_string (ctx, details->path);
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
  GumDukModule * module;
  const GArray * values;
  guint i;

  self = gumjs_module_map_from_args (args);
  module = gumjs_module_from_args (args);
  values = gum_module_map_get_values (self);

  duk_push_array (ctx);
  for (i = 0; i != values->len; i++)
  {
    GumModuleDetails * details;

    details = &g_array_index (values, GumModuleDetails, i);
    _gum_duk_push_module (ctx, details, module);
    duk_put_prop_index (ctx, -2, i);
  }

  return 1;
}

static void
gum_duk_module_filter_free (GumDukModuleFilter * filter)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (filter->module->core);

  _gum_duk_unprotect (scope.ctx, filter->callback);

  g_slice_free (GumDukModuleFilter, filter);
}

static gboolean
gum_duk_module_filter_matches (const GumModuleDetails * details,
                               GumDukModuleFilter * self)
{
  GumDukModule * module = self->module;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (module->core);
  duk_context * ctx = scope.ctx;
  gboolean result = FALSE;

  duk_push_heapptr (ctx, self->callback);
  _gum_duk_push_module (ctx, details, module);
  if (_gum_duk_scope_call (&scope, 1))
  {
    result = duk_is_boolean (ctx, -1) && duk_require_boolean (ctx, -1);
  }
  duk_pop (ctx);

  return result;
}
