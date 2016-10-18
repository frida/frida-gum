/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukmodule.h"

#include "gumdukmacros.h"

typedef struct _GumDukMatchContext GumDukMatchContext;

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

static const duk_function_list_entry gumjs_module_functions[] =
{
  { "enumerateImports", gumjs_module_enumerate_imports, 2 },
  { "enumerateExports", gumjs_module_enumerate_exports, 2 },
  { "enumerateRanges", gumjs_module_enumerate_ranges, 3 },
  { "findBaseAddress", gumjs_module_find_base_address, 1 },
  { "findExportByName", gumjs_module_find_export_by_name, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_module_init (GumDukModule * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_module_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "Module");
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
  (void) ctx;
  (void) args;

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
  _gum_duk_push_range (ctx, details, scope->core);

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
  GumAddress address;

  _gum_duk_args_parse (args, "s?s", &module_name, &symbol_name);

  address = gum_module_find_export_by_name (module_name, symbol_name);

  if (address != 0)
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (address), args->core);
  else
    duk_push_null (ctx);
  return 1;
}
