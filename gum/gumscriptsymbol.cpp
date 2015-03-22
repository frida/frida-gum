/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptsymbol.h"

#include "gumsymbolutil.h"

using namespace v8;

typedef struct _GumSymbol GumSymbol;

struct _GumSymbol
{
  GumPersistent<v8::Object>::type * instance;
  gboolean resolved;
  GumSymbolDetails details;
  GumScriptSymbol * module;
};

static void gum_script_symbol_on_from_address (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_symbol_on_from_name (
    const FunctionCallbackInfo<Value> & info);

static GumSymbol * gum_symbol_new (Handle<Object> instance,
    GumScriptSymbol * module);
static void gum_symbol_free (GumSymbol * symbol);
static void gum_symbol_on_weak_notify (const WeakCallbackData<Object,
    GumSymbol> & data);

static void gum_script_symbol_on_get_address (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_symbol_on_get_name (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_symbol_on_get_module_name (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_symbol_on_get_file_name (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_symbol_on_get_line_number (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_symbol_on_to_string (
    const FunctionCallbackInfo<Value> & info);

void
_gum_script_symbol_init (GumScriptSymbol * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> symbol = ObjectTemplate::New (isolate);
  symbol->Set (String::NewFromUtf8 (isolate, "fromAddress"),
      FunctionTemplate::New (isolate, gum_script_symbol_on_from_address,
      data));
  symbol->Set (String::NewFromUtf8 (isolate, "fromName"),
      FunctionTemplate::New (isolate, gum_script_symbol_on_from_name,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "DebugSymbol"), symbol);
}

void
_gum_script_symbol_realize (GumScriptSymbol * self)
{
  Isolate * isolate = self->core->isolate;

  self->symbols = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_symbol_free));

  Handle<ObjectTemplate> symbol = ObjectTemplate::New (isolate);
  symbol->SetInternalFieldCount (1);
  symbol->SetAccessor (String::NewFromUtf8 (isolate, "address"),
      gum_script_symbol_on_get_address);
  symbol->SetAccessor (String::NewFromUtf8 (isolate, "name"),
      gum_script_symbol_on_get_name);
  symbol->SetAccessor (String::NewFromUtf8 (isolate, "moduleName"),
      gum_script_symbol_on_get_module_name);
  symbol->SetAccessor (String::NewFromUtf8 (isolate, "fileName"),
      gum_script_symbol_on_get_file_name);
  symbol->SetAccessor (String::NewFromUtf8 (isolate, "lineNumber"),
      gum_script_symbol_on_get_line_number);
  symbol->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate, gum_script_symbol_on_to_string));
  self->value =
      new GumPersistent<Object>::type (isolate, symbol->NewInstance ());
}

void
_gum_script_symbol_dispose (GumScriptSymbol * self)
{
  g_hash_table_unref (self->symbols);
  self->symbols = NULL;

  delete self->value;
  self->value = NULL;
}

void
_gum_script_symbol_finalize (GumScriptSymbol * self)
{
  (void) self;
}

static void
gum_script_symbol_on_from_address (const FunctionCallbackInfo<Value> & info)
{
  GumScriptSymbol * self = static_cast<GumScriptSymbol *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  gpointer address;
  if (!_gum_script_pointer_get (info[0], &address, self->core))
    return;

  Local<Object> value (Local<Object>::New (isolate, *self->value));
  Local<Object> instance (value->Clone ());
  GumSymbol * symbol = gum_symbol_new (instance, self);
  symbol->details.address = GPOINTER_TO_SIZE (address);
  symbol->resolved =
      gum_symbol_details_from_address (address, &symbol->details);
  instance->SetAlignedPointerInInternalField (0, symbol);
  info.GetReturnValue ().Set (instance);
}

static void
gum_script_symbol_on_from_name (const FunctionCallbackInfo<Value> & info)
{
  GumScriptSymbol * self = static_cast<GumScriptSymbol *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> name_val = info[0];
  if (!name_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "DebugSymbol.fromName: argument must be a string "
        "specifying a symbol name")));
    return;
  }
  String::Utf8Value name (name_val);

  Local<Object> value (Local<Object>::New (isolate, *self->value));
  Local<Object> instance (value->Clone ());
  GumSymbol * symbol = gum_symbol_new (instance, self);
  gpointer address = gum_find_function (*name);
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
  instance->SetAlignedPointerInInternalField (0, symbol);
  info.GetReturnValue ().Set (instance);
}

static GumSymbol *
gum_symbol_new (Handle<Object> instance,
                GumScriptSymbol * module)
{
  GumSymbol * symbol;
  Isolate * isolate = module->core->isolate;

  symbol = g_slice_new (GumSymbol);
  symbol->instance = new GumPersistent<Object>::type (isolate, instance);
  symbol->instance->MarkIndependent ();
  symbol->instance->SetWeak (symbol, gum_symbol_on_weak_notify);
  symbol->module = module;

  isolate->AdjustAmountOfExternalAllocatedMemory (sizeof (GumSymbol));

  g_hash_table_insert (module->symbols, symbol, symbol);

  return symbol;
}

static void
gum_symbol_free (GumSymbol * symbol)
{
  symbol->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -static_cast<gssize> (sizeof (GumSymbol)));

  delete symbol->instance;
  g_slice_free (GumSymbol, symbol);
}

static void
gum_symbol_on_weak_notify (const WeakCallbackData<Object,
                           GumSymbol> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumSymbol * self = data.GetParameter ();
  g_hash_table_remove (self->module->symbols, self);
}

static void
gum_script_symbol_on_get_address (Local<String> property,
                                  const PropertyCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  (void) property;

  info.GetReturnValue ().Set (
      _gum_script_pointer_new (GSIZE_TO_POINTER (self->details.address),
          self->module->core));
}

static void
gum_script_symbol_on_get_name (Local<String> property,
                               const PropertyCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  (void) property;

  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (info.GetIsolate (), self->details.symbol_name));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_symbol_on_get_module_name (Local<String> property,
                                      const PropertyCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  (void) property;

  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (info.GetIsolate (), self->details.module_name));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_symbol_on_get_file_name (Local<String> property,
                                    const PropertyCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  (void) property;

  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (info.GetIsolate (), self->details.file_name));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_symbol_on_get_line_number (Local<String> property,
                                      const PropertyCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  (void) property;

  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        static_cast<uint32_t> (self->details.line_number));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_script_symbol_on_to_string (const FunctionCallbackInfo<Value> & info)
{
  GumSymbol * self = static_cast<GumSymbol *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumSymbolDetails * d = &self->details;
  gchar * str;

  if (self->resolved)
  {
    str = g_strdup_printf ("0x%" G_GINT64_MODIFIER "x %s!%s %s:%u",
        d->address,
        d->module_name, d->symbol_name,
        d->file_name, d->line_number);
  }
  else
  {
    str = g_strdup_printf ("0x%" G_GINT64_MODIFIER "x", d->address);
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (info.GetIsolate (), str));

  g_free (str);
}
