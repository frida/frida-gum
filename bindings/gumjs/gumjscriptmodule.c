/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptmodule.h"

#include "gumjscriptmacros.h"

#define GUMJS_MODULE_IMPORT_DETAILS(o) \
  ((GumImportDetails *) JSObjectGetPrivate (o))
#define GUMJS_MODULE_EXPORT_DETAILS(o) \
  ((GumExportDetails *) JSObjectGetPrivate (o))

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptModule * self;
  JSObjectRef on_match;
  JSObjectRef on_complete;
  JSContextRef ctx;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)

static JSObjectRef gumjs_module_import_new (JSContextRef ctx,
    const GumImportDetails * details, GumScriptModule * module);
GUMJS_DECLARE_FINALIZER (gumjs_module_import_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_type)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_name)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_module)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_address)

static JSObjectRef gumjs_module_export_new (JSContextRef ctx,
    const GumExportDetails * details, GumScriptModule * module);
GUMJS_DECLARE_FINALIZER (gumjs_module_export_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_type)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_name)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_address)

GUMJS_DECLARE_FUNCTION (gumjs_module_throw_not_yet_available)

static const JSStaticFunction gumjs_module_functions[] =
{
  { "enumerateImports", gumjs_module_enumerate_imports, GUMJS_RO },
  { "enumerateExports", gumjs_module_enumerate_exports, GUMJS_RO },
  { "enumerateRanges", gumjs_module_enumerate_ranges, GUMJS_RO },
  { "findBaseAddress", gumjs_module_find_base_address, GUMJS_RO },
  { "findExportByName", gumjs_module_throw_not_yet_available, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticValue gumjs_module_import_values[] =
{
  { "type", gumjs_module_import_get_type, NULL, GUMJS_RO },
  { "name", gumjs_module_import_get_name, NULL, GUMJS_RO },
  { "module", gumjs_module_import_get_module, NULL, GUMJS_RO },
  { "address", gumjs_module_import_get_address, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

static const JSStaticValue gumjs_module_export_values[] =
{
  { "type", gumjs_module_export_get_type, NULL, GUMJS_RO },
  { "name", gumjs_module_export_get_name, NULL, GUMJS_RO },
  { "address", gumjs_module_export_get_address, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

void
_gum_script_module_init (GumScriptModule * self,
                         GumScriptCore * core,
                         JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef module;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Module";
  def.staticFunctions = gumjs_module_functions;
  klass = JSClassCreate (&def);
  module = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, module);

  def = kJSClassDefinitionEmpty;
  def.className = "ModuleImport";
  def.staticValues = gumjs_module_import_values;
  def.finalize = gumjs_module_import_finalize;
  self->module_import = JSClassCreate (&def);

  def = kJSClassDefinitionEmpty;
  def.className = "ModuleExport";
  def.staticValues = gumjs_module_export_values;
  def.finalize = gumjs_module_export_finalize;
  self->module_export = JSClassCreate (&def);
}

void
_gum_script_module_dispose (GumScriptModule * self)
{
  g_clear_pointer (&self->module_export, JSClassRelease);
  g_clear_pointer (&self->module_import, JSClassRelease);
}

void
_gum_script_module_finalize (GumScriptModule * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumScriptMatchContext mc;
  gchar * name;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_module_enumerate_imports (name, gum_emit_import, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_script_scope_flush (&scope);

  g_free (name);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumScriptMatchContext * mc = user_data;
  GumScriptModule * module = mc->self;
  GumScriptCore * core = module->core;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef imp;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  imp = gumjs_module_import_new (ctx, details, module);

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &imp, &scope.exception);
  _gum_script_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumScriptMatchContext mc;
  gchar * name;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_module_enumerate_exports (name, gum_emit_export, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_script_scope_flush (&scope);

  g_free (name);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 gpointer user_data)
{
  GumScriptMatchContext * mc = user_data;
  GumScriptModule * module = mc->self;
  GumScriptCore * core = module->core;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef exp;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  exp = gumjs_module_export_new (ctx, details, module);

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &exp, &scope.exception);
  _gum_script_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumScriptMatchContext mc;
  gchar * name;
  GumPageProtection prot;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_module_enumerate_ranges (name, prot, gum_emit_range, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_script_scope_flush (&scope);

  g_free (name);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                gpointer user_data)
{
  GumScriptMatchContext * mc = user_data;
  GumScriptCore * core = mc->self->core;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  char prot_str[4] = "---";
  JSObjectRef range;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  range = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_pointer (ctx, range, "base",
      GSIZE_TO_POINTER (details->range->base_address), core);
  _gumjs_object_set_uint (ctx, range, "size", details->range->size);
  _gumjs_object_set_string (ctx, range, "protection", prot_str);

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &range, &scope.exception);
  _gum_script_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  GumScriptCore * core = args->core;
  gchar * name;
  GumAddress address;

  if (!_gumjs_args_parse (args, "s", &name))
    return NULL;

  address = gum_module_find_base_address (name);

  g_free (name);

  if (address != 0)
    return _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
  else
    return JSValueMakeNull (ctx);
}

static JSObjectRef
gumjs_module_import_new (JSContextRef ctx,
                         const GumImportDetails * details,
                         GumScriptModule * module)
{
  GumImportDetails * d;

  d = g_slice_dup (GumImportDetails, details);
  d->name = g_strdup (details->name);
  d->module = g_strdup (details->module);

  return JSObjectMake (ctx, module->module_import, d);
}

GUMJS_DEFINE_FINALIZER (gumjs_module_import_finalize)
{
  GumImportDetails * details = GUMJS_MODULE_IMPORT_DETAILS (object);

  g_free ((gchar *) details->name);
  g_free ((gchar *) details->module);

  g_slice_free (GumImportDetails, details);
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_type)
{
  GumImportDetails * details = GUMJS_MODULE_IMPORT_DETAILS (object);

  if (details->type == GUM_IMPORT_UNKNOWN)
    return NULL;

  return _gumjs_string_to_value (ctx,
      (details->type == GUM_IMPORT_FUNCTION) ? "function" : "variable");
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_name)
{
  GumImportDetails * details = GUMJS_MODULE_IMPORT_DETAILS (object);

  return _gumjs_string_to_value (ctx, details->name);
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_module)
{
  GumImportDetails * details = GUMJS_MODULE_IMPORT_DETAILS (object);

  if (details->module == NULL)
    return NULL;

  return _gumjs_string_to_value (ctx, details->module);
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_address)
{
  GumImportDetails * details = GUMJS_MODULE_IMPORT_DETAILS (object);

  if (details->address == 0)
    return NULL;

  return _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
      args->core);
}

static JSObjectRef
gumjs_module_export_new (JSContextRef ctx,
                         const GumExportDetails * details,
                         GumScriptModule * module)
{
  GumExportDetails * d;

  d = g_slice_dup (GumExportDetails, details);
  d->name = g_strdup (details->name);

  return JSObjectMake (ctx, module->module_export, d);
}

GUMJS_DEFINE_FINALIZER (gumjs_module_export_finalize)
{
  GumExportDetails * details = GUMJS_MODULE_EXPORT_DETAILS (object);

  g_free ((gchar *) details->name);

  g_slice_free (GumExportDetails, details);
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_type)
{
  GumExportDetails * details = GUMJS_MODULE_EXPORT_DETAILS (object);

  return _gumjs_string_to_value (ctx,
      (details->type == GUM_EXPORT_FUNCTION) ? "function" : "variable");
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_name)
{
  GumExportDetails * details = GUMJS_MODULE_EXPORT_DETAILS (object);

  return _gumjs_string_to_value (ctx, details->name);
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_address)
{
  GumExportDetails * details = GUMJS_MODULE_EXPORT_DETAILS (object);

  return _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
      args->core);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "Module API not yet available in the JavaScriptCore runtime");
  return NULL;
}
