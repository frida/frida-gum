/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscsymbol.h"

#include "gumjscmacros.h"

#include <gum/gumsymbolutil.h>

#define GUMJS_SYMBOL(o) \
  ((GumSymbol *) JSObjectGetPrivate (o))

typedef struct _GumSymbol GumSymbol;

struct _GumSymbol
{
  gboolean resolved;
  GumSymbolDetails details;
};

GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_address)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_get_function_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_named)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_matching)

static JSObjectRef gumjs_symbol_new (JSContextRef ctx, GumJscSymbol * parent,
    GumSymbol ** symbol);
GUMJS_DECLARE_FINALIZER (gumjs_symbol_finalize)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_address)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_module_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_line_number)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_string)
GUMJS_DECLARE_CONVERTER (gumjs_symbol_convert_to_type)

static JSObjectRef gumjs_pointer_array_to_value (JSContextRef ctx,
    GArray * pointers, GumJscCore * core, JSValueRef * exception);

static const JSStaticFunction gumjs_symbol_module_functions[] =
{
  { "fromAddress", gumjs_symbol_from_address, GUMJS_RO },
  { "fromName", gumjs_symbol_from_name, GUMJS_RO },
  { "getFunctionByName", gumjs_symbol_get_function_by_name, GUMJS_RO },
  { "findFunctionsNamed", gumjs_symbol_find_functions_named, GUMJS_RO },
  { "findFunctionsMatching", gumjs_symbol_find_functions_matching, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticValue gumjs_symbol_values[] =
{
  { "address", gumjs_symbol_get_address, NULL, GUMJS_RO },
  { "name", gumjs_symbol_get_name, NULL, GUMJS_RO },
  { "moduleName", gumjs_symbol_get_module_name, NULL, GUMJS_RO },
  { "fileName", gumjs_symbol_get_file_name, NULL, GUMJS_RO },
  { "lineNumber", gumjs_symbol_get_line_number, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_symbol_functions[] =
{
  { "toString", gumjs_symbol_to_string, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_jsc_symbol_init (GumJscSymbol * self,
                      GumJscCore * core,
                      JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef module;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "DebugSymbolModule";
  def.staticFunctions = gumjs_symbol_module_functions;
  klass = JSClassCreate (&def);
  module = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "DebugSymbol", module);

  def = kJSClassDefinitionEmpty;
  def.className = "DebugSymbol";
  def.staticValues = gumjs_symbol_values;
  def.staticFunctions = gumjs_symbol_functions;
  def.finalize = gumjs_symbol_finalize;
  def.convertToType = gumjs_symbol_convert_to_type;
  self->symbol = JSClassCreate (&def);
}

void
_gum_jsc_symbol_dispose (GumJscSymbol * self)
{
  g_clear_pointer (&self->symbol, JSClassRelease);
}

void
_gum_jsc_symbol_finalize (GumJscSymbol * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_address)
{
  GumJscSymbol * self;
  gpointer address;
  GumSymbol * symbol;
  JSObjectRef instance;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "p", &address))
    return NULL;

  instance = gumjs_symbol_new (ctx, self, &symbol);
  symbol->details.address = GPOINTER_TO_SIZE (address);
  symbol->resolved =
      gum_symbol_details_from_address (address, &symbol->details);
  return instance;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_name)
{
  GumJscSymbol * self;
  gchar * name;
  GumSymbol * symbol;
  JSObjectRef instance;
  gpointer address;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "s", &name))
    return NULL;

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

  g_free (name);

  return instance;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_get_function_by_name)
{
  GumJscSymbol * self;
  gchar * name;
  gpointer address;
  JSValueRef result;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "s", &name))
    return NULL;

  address = gum_find_function (name);
  if (address != NULL)
  {
    result = _gumjs_native_pointer_new (ctx, address, args->core);
  }
  else
  {
    result = NULL;
    _gumjs_throw (ctx, exception, "unable to find function with name '%s'",
        name);
  }

  g_free (name);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_named)
{
  GumJscSymbol * self;
  gchar * name;
  GArray * functions;
  JSObjectRef result;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "s", &name))
    return NULL;

  functions = gum_find_functions_named (name);
  result = gumjs_pointer_array_to_value (ctx, functions, args->core, exception);
  g_array_free (functions, TRUE);

  g_free (name);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_matching)
{
  GumJscSymbol * self;
  gchar * str;
  GArray * functions;
  JSObjectRef result;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "s", &str))
    return NULL;

  functions = gum_find_functions_matching (str);
  result = gumjs_pointer_array_to_value (ctx, functions, args->core, exception);
  g_array_free (functions, TRUE);

  g_free (str);

  return result;
}

static JSObjectRef
gumjs_symbol_new (JSContextRef ctx,
                  GumJscSymbol * parent,
                  GumSymbol ** symbol)
{
  GumSymbol * s;

  s = g_slice_new (GumSymbol);
  s->resolved = FALSE;

  *symbol = s;

  return JSObjectMake (ctx, parent->symbol, s);
}

static JSValueRef
gum_symbol_to_string (GumSymbol * self,
                      JSContextRef ctx)
{
  GumSymbolDetails * d = &self->details;
  GString * s;
  JSValueRef result;

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

  result = _gumjs_string_to_value (ctx, s->str);

  g_string_free (s, TRUE);

  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_symbol_finalize)
{
  GumSymbol * symbol = GUMJS_SYMBOL (object);

  g_slice_free (GumSymbol, symbol);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_address)
{
  GumSymbol * self = GUMJS_SYMBOL (object);

  return _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->details.address), args->core);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_name)
{
  GumSymbol * self = GUMJS_SYMBOL (object);

  if (self->resolved)
    return _gumjs_string_to_value (ctx, self->details.symbol_name);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_module_name)
{
  GumSymbol * self = GUMJS_SYMBOL (object);

  if (self->resolved)
    return _gumjs_string_to_value (ctx, self->details.module_name);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_file_name)
{
  GumSymbol * self = GUMJS_SYMBOL (object);

  if (self->resolved)
    return _gumjs_string_to_value (ctx, self->details.file_name);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_line_number)
{
  GumSymbol * self = GUMJS_SYMBOL (object);

  if (self->resolved)
    return JSValueMakeNumber (ctx, self->details.line_number);
  else
    return JSValueMakeNull (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_to_string)
{
  return gum_symbol_to_string (GUMJS_SYMBOL (this_object), ctx);
}

GUMJS_DEFINE_CONVERTER (gumjs_symbol_convert_to_type)
{
  if (type != kJSTypeString)
    return NULL;

  return gum_symbol_to_string (GUMJS_SYMBOL (object), ctx);
}

static JSObjectRef
gumjs_pointer_array_to_value (JSContextRef ctx,
                              GArray * pointers,
                              GumJscCore * core,
                              JSValueRef * exception)
{
  JSValueRef * elements;
  guint i;
  JSObjectRef array;

  elements = g_new (JSValueRef, pointers->len);

  for (i = 0; i != pointers->len; i++)
  {
    gpointer address = g_array_index (pointers, gpointer, i);
    elements[i] = _gumjs_native_pointer_new (ctx, address, core);
  }

  array = JSObjectMakeArray (ctx, pointers->len, elements, exception);

  g_free (elements);

  return array;
}
