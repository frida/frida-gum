/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukmodule.h"

#include "gumdukmacros.h"

#define GUMJS_MODULE_IMPORT_DETAILS(o) \
  ((GumImportDetails *) _gumjs_get_private_data (ctx, o))
#define GUMJS_MODULE_EXPORT_DETAILS(o) \
  ((GumExportDetails *) _gumjs_get_private_data (ctx, o))

typedef struct _GumDukMatchContext GumDukMatchContext;

struct _GumDukMatchContext
{
  GumDukModule * self;
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;
  duk_context * ctx;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
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
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_import_construct)
static GumDukHeapPtr gumjs_module_import_new (duk_context * ctx,
    const GumImportDetails * details, GumDukModule * parent);
GUMJS_DECLARE_FINALIZER (gumjs_module_import_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_type)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_name)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_module)
GUMJS_DECLARE_GETTER (gumjs_module_import_get_address)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_export_construct)
static GumDukHeapPtr gumjs_module_export_new (duk_context * ctx,
    const GumExportDetails * details, GumDukModule * parent);
GUMJS_DECLARE_FINALIZER (gumjs_module_export_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_type)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_name)
GUMJS_DECLARE_GETTER (gumjs_module_export_get_address)

static const duk_function_list_entry gumjs_module_functions[] =
{
  { "enumerateImports", gumjs_module_enumerate_imports, 2 },
  { "enumerateExports", gumjs_module_enumerate_exports, 2 },
  { "enumerateRanges", gumjs_module_enumerate_ranges, 3 },
  { "findBaseAddress", gumjs_module_find_base_address, 1 },
  { "findExportByName", gumjs_module_find_export_by_name, 2 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_module_import_values[] =
{
  { "type", gumjs_module_import_get_type, NULL},
  { "name", gumjs_module_import_get_name, NULL},
  { "module", gumjs_module_import_get_module, NULL},
  { "address", gumjs_module_import_get_address, NULL},

  { NULL, NULL, NULL}
};

static const GumDukPropertyEntry gumjs_module_export_values[] =
{
  { "type", gumjs_module_export_get_type, NULL},
  { "name", gumjs_module_export_get_name, NULL},
  { "address", gumjs_module_export_get_address, NULL},

  { NULL, NULL, NULL}
};

void
_gum_duk_module_init (GumDukModule * self,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_module_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_put_function_list (ctx, -1, gumjs_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Module");
  // []

  duk_push_c_function (ctx, gumjs_module_import_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_push_c_function (ctx, gumjs_module_import_finalize, 0);
  // [ construct proto finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct proto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  self->module_import = duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "ModuleImport");
  // []
  _gumjs_duk_add_properties_to_class (ctx, "ModuleImport",
      gumjs_module_import_values);

  duk_push_c_function (ctx, gumjs_module_export_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_push_c_function (ctx, gumjs_module_export_finalize, 0);
  // [ construct proto finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct proto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  self->module_export = duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "ModuleExport");
  // []
  _gumjs_duk_add_properties_to_class (ctx, "ModuleExport",
      gumjs_module_export_values);
}

void
_gum_duk_module_dispose (GumDukModule * self)
{
    (void) self;
}

void
_gum_duk_module_finalize (GumDukModule * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_construct)
{
  return 0;
}
GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumDukMatchContext mc;
  gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }
  mc.ctx = ctx;

  gum_module_enumerate_imports (name, gum_emit_import, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  // [ on_complete ]
  duk_call (ctx, 0);
  // [ result ]
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukModule * self = mc->self;
  GumDukCore * core = self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  GumDukHeapPtr imp;
  const gchar * result;
  gboolean proceed;

  imp = gumjs_module_import_new (ctx, details, self);

  duk_push_heapptr (ctx, mc->on_match);
  // [ on_match ]
  duk_push_heapptr (ctx, imp);
  _gumjs_duk_release_heapptr (ctx, imp);
  // [ on_match imp ]
  duk_call (ctx, 1);
  // [ result ]
  result = duk_safe_to_string (ctx, -1);
  proceed = strcmp (result, "stop") != 0;
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumDukMatchContext mc;
  gchar * name;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }
  mc.ctx = ctx;

  gum_module_enumerate_exports (name, gum_emit_export, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  // [ on_complete ]
  duk_call (ctx, 0);
  // [ result ]
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukModule * self = mc->self;
  GumDukCore * core = self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  GumDukHeapPtr exp;
  const gchar * result;
  gboolean proceed;

  exp = gumjs_module_export_new (ctx, details, self);

  duk_push_heapptr (ctx, mc->on_match);
  // [ on_match ]
  duk_push_heapptr (ctx, exp);
  _gumjs_duk_release_heapptr (ctx, exp);
  // [ on_match imp ]
  duk_call (ctx, 1);
  // [ result ]
  result = duk_safe_to_string (ctx, -1);
  proceed = strcmp (result, "stop") != 0;
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumDukMatchContext mc;
  gchar * name;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }
  mc.ctx = ctx;

  gum_module_enumerate_ranges (name, prot, gum_emit_range, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  // [ on_complete ]
  duk_call (ctx, 0);
  // [ result ]
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukCore * core = mc->self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  char prot_str[4] = "---";
  GumDukHeapPtr range, pointer;
  const gchar * result;
  gboolean proceed;

  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  duk_push_object (ctx);
  // [ newobj ]
  pointer = _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (details->range->base_address), core);
  duk_push_heapptr (ctx, pointer);
  _gumjs_duk_release_heapptr (ctx, pointer);
  // [ newobj base ]
  duk_put_prop_string (ctx, -2, "base");
  // [ newobj ]
  duk_push_uint (ctx, details->range->size);
  // [ newobj size ]
  duk_put_prop_string (ctx, -2, "size");
  // [ newobj ]
  duk_push_string (ctx, prot_str);
  // [ newobj prot_str ]
  duk_put_prop_string (ctx, -2, "protection");
  // [ newobj ]
  range = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  duk_push_heapptr (ctx, mc->on_match);
  // [ on_match ]
  duk_push_heapptr (ctx, range);
  _gumjs_duk_release_heapptr (ctx, range);
  // [ on_match range ]
  duk_call (ctx, 1);
  // [ result ]
  result = duk_safe_to_string (ctx, -1);
  proceed = strcmp (result, "stop") != 0;
  duk_pop (ctx);
  // []

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  GumDukCore * core = args->core;
  gchar * name;
  GumAddress address;
  GumDukHeapPtr result;

  if (!_gumjs_args_parse (ctx, "s", &name))
  {
    duk_push_null (ctx);
    return 1;
  }

  address = gum_module_find_base_address (name);

  if (address != 0)
  {
    result =_gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
    duk_push_heapptr (ctx, result);
    _gumjs_duk_release_heapptr (ctx, result);
  }
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  GumDukCore * core = args->core;
  gchar * module_name, * symbol_name;
  GumAddress address;
  GumDukHeapPtr result;

  if (!_gumjs_args_parse (ctx, "s?s", &module_name, &symbol_name))
  {
    duk_push_null (ctx);
    return 1;
  }

  address = gum_module_find_export_by_name (module_name, symbol_name);

  if (address != 0)
  {
    result =_gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
    duk_push_heapptr (ctx, result);
    _gumjs_duk_release_heapptr (ctx, result);
  }
  else
  {
    duk_push_null (ctx);
  }

  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_import_construct)
{
  return 0;
}

static GumDukHeapPtr
gumjs_module_import_new (duk_context * ctx,
                         const GumImportDetails * details,
                         GumDukModule * parent)
{
  GumImportDetails * d;
  GumDukHeapPtr result;

  d = g_slice_dup (GumImportDetails, details);
  d->name = g_strdup (details->name);
  d->module = g_strdup (details->module);

  duk_push_heapptr (ctx, parent->module_import);
  // [ module_import ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), d);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_module_import_finalize)
{
  GumImportDetails * details;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "ModuleImport"))
    return 0;

  details = GUMJS_MODULE_IMPORT_DETAILS (duk_require_heapptr (ctx, 0));

  g_free ((gchar *) details->name);
  g_free ((gchar *) details->module);

  g_slice_free (GumImportDetails, details);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_type)
{
  GumImportDetails * details;

  details = GUMJS_MODULE_IMPORT_DETAILS (_gumjs_duk_get_this (ctx));

  if (details->type == GUM_IMPORT_UNKNOWN)
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_string (ctx,
      (details->type == GUM_IMPORT_FUNCTION) ? "function" : "variable");
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_name)
{
  GumImportDetails * details;

  details = GUMJS_MODULE_IMPORT_DETAILS (_gumjs_duk_get_this (ctx));

  duk_push_string (ctx, details->name);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_module)
{
  GumImportDetails * details;

  details = GUMJS_MODULE_IMPORT_DETAILS (_gumjs_duk_get_this (ctx));

  if (details->module == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_string (ctx, details->module);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_module_import_get_address)
{
  GumImportDetails * details;
  GumDukHeapPtr result;

  details = GUMJS_MODULE_IMPORT_DETAILS (_gumjs_duk_get_this (ctx));

  if (details->address == 0)
  {
    duk_push_null (ctx);
    return 1;
  }

  result = _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
      args->core);
  duk_push_heapptr (ctx, result);
  _gumjs_duk_release_heapptr (ctx, result);
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_export_construct)
{
  return 0;
}

static GumDukHeapPtr
gumjs_module_export_new (duk_context * ctx,
                         const GumExportDetails * details,
                         GumDukModule * parent)
{
  GumExportDetails * d;
  GumDukHeapPtr result;

  d = g_slice_dup (GumExportDetails, details);
  d->name = g_strdup (details->name);

  duk_push_heapptr (ctx, parent->module_export);
  // [ module_import ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), d);

  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_module_export_finalize)
{
  GumExportDetails * details;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "ModuleExport"))
    return 0;

  details = GUMJS_MODULE_EXPORT_DETAILS (duk_require_heapptr (ctx, 0));

  g_free ((gchar *) details->name);

  g_slice_free (GumExportDetails, details);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_type)
{
  GumExportDetails * details;

  details = GUMJS_MODULE_EXPORT_DETAILS (_gumjs_duk_get_this (ctx));

  duk_push_string (ctx,
      (details->type == GUM_EXPORT_FUNCTION) ? "function" : "variable");
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_name)
{
  GumExportDetails * details;

  details = GUMJS_MODULE_EXPORT_DETAILS (_gumjs_duk_get_this (ctx));

  duk_push_string (ctx, details->name);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_module_export_get_address)
{
  GumExportDetails * details;
  GumDukHeapPtr result;

  details = GUMJS_MODULE_EXPORT_DETAILS (_gumjs_duk_get_this (ctx));

  result = _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
      args->core);
  duk_push_heapptr (ctx, result);
  _gumjs_duk_release_heapptr (ctx, result);
  return 1;
}
