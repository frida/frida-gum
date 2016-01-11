/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksymbol.h"

#include "gumdukmacros.h"

#include <gum/gumsymbolutil.h>

GUMJS_DECLARE_CONSTRUCTOR (gumjs_symbol_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_address)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_get_function_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_named)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_matching)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_symbol_construct)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_string)

static void gumjs_pointer_array_push (duk_context * ctx, GArray * pointers,
    GumDukCore * core);

static const duk_function_list_entry gumjs_symbol_module_functions[] =
{
  { "fromAddress", gumjs_symbol_from_address, 1 },
  { "fromName", gumjs_symbol_from_name, 1 },
  { "getFunctionByName", gumjs_symbol_get_function_by_name, 1 },
  { "findFunctionsNamed", gumjs_symbol_find_functions_named, 1 },
  { "findFunctionsMatching", gumjs_symbol_find_functions_matching, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_symbol_functions[] =
{
  { "toString", gumjs_symbol_to_string, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_symbol_init (GumDukSymbol * self,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_symbol_module_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_symbol_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "DebugSymbol");

  duk_push_c_function (ctx, gumjs_symbol_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_symbol_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->symbol = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
}

void
_gum_duk_symbol_dispose (GumDukSymbol * self)
{
  _gumjs_duk_release_heapptr (self->core->ctx, self->symbol);
  self->symbol = NULL;
}

void
_gum_duk_symbol_finalize (GumDukSymbol * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_symbol_module_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_address)
{
  GumDukSymbol * self;
  gpointer address;
  GumSymbolDetails details;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  _gum_duk_require_args (ctx, "p", &address);

  duk_push_heapptr (ctx, self->symbol);
  duk_push_pointer (ctx, address);
  if (gum_symbol_details_from_address (address, &details))
    duk_push_pointer (ctx, &details);
  else
    duk_push_pointer (ctx, NULL);
  duk_new (ctx, 2);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_name)
{
  GumDukSymbol * self;
  const gchar * name;
  gpointer address;
  GumSymbolDetails details;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  _gum_duk_require_args (ctx, "s", &name);

  duk_push_heapptr (ctx, self->symbol);
  address = gum_find_function (name);
  duk_push_pointer (ctx, address);
  if (address != NULL && gum_symbol_details_from_address (address, &details))
    duk_push_pointer (ctx, &details);
  else
    duk_push_pointer (ctx, NULL);
  duk_new (ctx, 2);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_get_function_by_name)
{
  const gchar * name;
  gpointer address;

  _gum_duk_require_args (ctx, "s", &name);

  address = gum_find_function (name);
  if (address == NULL)
    _gumjs_throw (ctx, "unable to find function with name '%s'", name);

  _gumjs_native_pointer_push (ctx, address, args->core);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_named)
{
  gchar * name;
  GArray * functions;

  _gum_duk_require_args (ctx, "s", &name);

  functions = gum_find_functions_named (name);
  gumjs_pointer_array_push (ctx, functions, args->core);
  g_array_free (functions, TRUE);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_matching)
{
  const gchar * str;
  GArray * functions;

  _gum_duk_require_args (ctx, "s", &str);

  functions = gum_find_functions_matching (str);
  gumjs_pointer_array_push (ctx, functions, args->core);
  g_array_free (functions, TRUE);
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_symbol_construct)
{
  gpointer address;
  GumSymbolDetails * d;
  GString * s;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "Constructor call required");
    duk_throw (ctx);
  }

  address = duk_require_pointer (ctx, 0);
  d = duk_require_pointer (ctx, 1);

  duk_push_this (ctx);

  _gumjs_native_pointer_push (ctx, address, args->core);
  duk_put_prop_string (ctx, -2, "address");

  if (d != NULL)
    duk_push_string (ctx, d->symbol_name);
  else
    duk_push_null (ctx);
  duk_put_prop_string (ctx, -2, "name");

  if (d != NULL)
    duk_push_string (ctx, d->module_name);
  else
    duk_push_null (ctx);
  duk_put_prop_string (ctx, -2, "moduleName");

  if (d != NULL)
    duk_push_string (ctx, d->file_name);
  else
    duk_push_null (ctx);
  duk_put_prop_string (ctx, -2, "fileName");

  if (d != NULL)
    duk_push_number (ctx, d->line_number);
  else
    duk_push_null (ctx);
  duk_put_prop_string (ctx, -2, "lineNumber");

  s = g_string_new ("0");

  if (d != NULL)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x %s!%s",
        d->address,
        d->module_name, d->symbol_name);
    if (d->file_name[0] != '\0')
    {
      g_string_append_printf (s, " %s:%u", d->file_name, d->line_number);
    }
  }
  else if (address != NULL)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x",
        GUM_ADDRESS (address));
  }

  duk_push_string (ctx, s->str);

  g_string_free (s, TRUE);

  duk_put_prop_string (ctx, -2, "\xff" "description");

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_to_string)
{
  duk_push_this (ctx);
  duk_get_prop_string (ctx, -1, "\xff" "description");
  return 1;
}

static void
gumjs_pointer_array_push (duk_context * ctx,
                          GArray * pointers,
                          GumDukCore * core)
{
  guint i;

  duk_push_array (ctx);

  for (i = 0; i != pointers->len; i++)
  {
    gpointer address = g_array_index (pointers, gpointer, i);
    _gumjs_native_pointer_push (ctx, address, core);
    duk_put_prop_index (ctx, -2, i);
  }
}
