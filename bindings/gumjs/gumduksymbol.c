/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumduksymbol.h"

#include "gumdukmacros.h"

#include <gum/gumsymbolutil.h>

#define GUMJS_SYMBOL(o) \
  ((GumSymbol *) _gumjs_get_private_data (ctx, o))

typedef struct _GumSymbol GumSymbol;

struct _GumSymbol
{
  gboolean resolved;
  GumSymbolDetails details;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_symbol_construct)
GUMJS_DECLARE_CONSTRUCTOR (gumjs_symbol_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_address)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_get_function_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_named)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_matching)

static GumDukHeapPtr gumjs_symbol_new (duk_context * ctx, GumDukSymbol * parent,
    GumSymbol ** symbol);
GUMJS_DECLARE_FINALIZER (gumjs_symbol_finalize)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_address)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_module_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_line_number)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_string)

static GumDukHeapPtr gumjs_pointer_array_to_value (duk_context * ctx,
    GArray * pointers, GumDukCore * core);

static const duk_function_list_entry gumjs_symbol_module_functions[] =
{
  { "fromAddress", gumjs_symbol_from_address, 1 },
  { "fromName", gumjs_symbol_from_name, 1 },
  { "getFunctionByName", gumjs_symbol_get_function_by_name, 1 },
  { "findFunctionsNamed", gumjs_symbol_find_functions_named, 1 },
  { "findFunctionsMatching", gumjs_symbol_find_functions_matching, 1 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_symbol_values[] =
{
  { "address", gumjs_symbol_get_address, NULL },
  { "name", gumjs_symbol_get_name, NULL},
  { "moduleName", gumjs_symbol_get_module_name, NULL},
  { "fileName", gumjs_symbol_get_file_name, NULL},
  { "lineNumber", gumjs_symbol_get_line_number, NULL},

  { NULL, NULL, NULL}
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
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_put_function_list (ctx, -1, gumjs_symbol_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "DebugSymbol");
  // []

  duk_push_c_function (ctx, gumjs_symbol_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct proto ]
  duk_put_function_list (ctx, -1, gumjs_symbol_functions);
  duk_push_c_function (ctx, gumjs_symbol_finalize, 0);
  // [ construct proto finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct proto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  self->symbol = _gumjs_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "DebugSymbolItem");
  // []
  _gumjs_duk_add_properties_to_class (ctx, "DebugSymbolItem",
      gumjs_symbol_values);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_symbol_construct)
{
  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_symbol_module_construct)
{
  return 0;
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

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_address)
{
  GumDukSymbol * self;
  gpointer address;
  GumSymbol * symbol;
  GumDukHeapPtr instance;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "p", &address))
  {
    duk_push_null (ctx);
    return 1;
  }

  instance = gumjs_symbol_new (ctx, self, &symbol);
  symbol->details.address = GPOINTER_TO_SIZE (address);
  symbol->resolved =
      gum_symbol_details_from_address (address, &symbol->details);

  duk_push_heapptr (ctx, instance);
  _gumjs_duk_release_heapptr (ctx, instance);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_name)
{
  GumDukSymbol * self;
  gchar * name;
  GumSymbol * symbol;
  GumDukHeapPtr instance;
  gpointer address;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "s", &name))
  {
    duk_push_null (ctx);
    return 1;
  }

  instance = gumjs_symbol_new (ctx, self, &symbol);

  address = gum_find_function (name);
  if (address != NULL)
  {
    symbol->resolved =
        gum_symbol_details_from_address (address, &symbol->details);
  }
  else
  {
    symbol->resolved = FALSE;
    symbol->details.address = 0;
  }

  duk_push_heapptr (ctx, instance);
  _gumjs_duk_release_heapptr (ctx, instance);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_get_function_by_name)
{
  GumDukSymbol * self;
  gchar * name;
  gpointer address;
  GumDukHeapPtr result;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "s", &name))
  {
    duk_push_null (ctx);
    return 1;
  }

  address = gum_find_function (name);
  if (address != NULL)
  {
    result = _gumjs_native_pointer_new (ctx, address, args->core);
  }
  else
  {
    result = NULL;
    _gumjs_throw (ctx, "unable to find function with name '%s'",
        name);
  }

  duk_push_heapptr (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_named)
{
  GumDukSymbol * self;
  gchar * name;
  GArray * functions;
  GumDukHeapPtr result;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "s", &name))
  {
    duk_push_null (ctx);
    return 1;
  }

  functions = gum_find_functions_named (name);
  result = gumjs_pointer_array_to_value (ctx, functions, args->core);
  g_array_free (functions, TRUE);

  duk_push_heapptr (ctx, result);
  _gumjs_duk_release_heapptr (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_matching)
{
  GumDukSymbol * self;
  gchar * str;
  GArray * functions;
  GumDukHeapPtr result;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "s", &str))
  {
    duk_push_null (ctx);
    return 1;
  }

  functions = gum_find_functions_matching (str);
  result = gumjs_pointer_array_to_value (ctx, functions, args->core);
  g_array_free (functions, TRUE);

  duk_push_heapptr (ctx, result);
  return 1;
}

static GumDukHeapPtr
gumjs_symbol_new (duk_context * ctx,
                  GumDukSymbol * parent,
                  GumSymbol ** symbol)
{
  GumSymbol * s;
  GumDukHeapPtr result;

  s = g_slice_new (GumSymbol);
  s->resolved = FALSE;

  *symbol = s;

  duk_push_heapptr (ctx, parent->symbol);
  // [ DebugSymbolInstance ]
  duk_new (ctx, 0);
  // [ instance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), s);
  result = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  return result;
}

static GumDukHeapPtr
gum_symbol_to_string (GumSymbol * self,
                      duk_context * ctx)
{
  GumSymbolDetails * d = &self->details;
  GString * s;
  GumDukHeapPtr result;

  s = g_string_new ("0");

  if (self->resolved)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x %s!%s",
        d->address,
        d->module_name, d->symbol_name);
    if (d->file_name[0] != '\0')
    {
      g_string_append_printf (s, " %s:%u", d->file_name, d->line_number);
    }
  }
  else if (d->address != 0)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x", d->address);
  }

  duk_push_string (ctx, s->str);
  result = (GumDukHeapPtr) duk_require_string (ctx, -1);

  g_string_free (s, TRUE);

  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_symbol_finalize)
{
  GumSymbol * symbol;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "DebugSymbol"))
    return 0;

  symbol = GUMJS_SYMBOL (duk_require_heapptr (ctx, 0));

  g_slice_free (GumSymbol, symbol);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_address)
{
  GumSymbol * self;
  GumDukHeapPtr result;

  self = GUMJS_SYMBOL (_gumjs_duk_get_this (ctx));

  result = _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->details.address), args->core);
  duk_push_heapptr (ctx, result);
  _gumjs_duk_release_heapptr (ctx, result);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_name)
{
  GumSymbol * self = GUMJS_SYMBOL (_gumjs_duk_get_this (ctx));

  if (self->resolved)
    duk_push_string (ctx, self->details.symbol_name);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_module_name)
{
  GumSymbol * self = GUMJS_SYMBOL (_gumjs_duk_get_this (ctx));

  if (self->resolved)
    duk_push_string (ctx, self->details.module_name);
  else
    duk_push_null(ctx);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_file_name)
{
  GumSymbol * self = GUMJS_SYMBOL (_gumjs_duk_get_this (ctx));

  if (self->resolved)
    duk_push_string (ctx, self->details.file_name);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_line_number)
{
  GumSymbol * self = GUMJS_SYMBOL (_gumjs_duk_get_this (ctx));

  if (self->resolved)
    duk_push_number (ctx, self->details.line_number);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_to_string)
{
  gum_symbol_to_string (GUMJS_SYMBOL (_gumjs_duk_get_this (ctx)), ctx);
  return 1;
}

static GumDukHeapPtr
gumjs_pointer_array_to_value (duk_context * ctx,
                              GArray * pointers,
                              GumDukCore * core)
{
  guint i;
  GumDukHeapPtr item, array;

  duk_push_array (ctx);
  // [ array ]

  for (i = 0; i != pointers->len; i++)
  {
    gpointer address = g_array_index (pointers, gpointer, i);
    item = _gumjs_native_pointer_new (ctx, address, core);
    duk_push_heapptr (ctx, item);
    // [ array item ]
    _gumjs_duk_release_heapptr (ctx, item);
    duk_put_prop_index (ctx, -2, i);
    // [ array ]
  }

  array = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []
  return array;
}
