/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8cmodule.h"

#include "gumcmodule.h"
#include "gumv8macros.h"

#define GUMJS_MODULE_NAME CModule

using namespace v8;

struct GumCModuleEntry
{
  GumPersistent<Object>::type * wrapper;
  GumPersistent<Object>::type * symbols;
  GumCModule * handle;
  GumV8CModule * module;
};

struct GumAddCSymbolsContext
{
  Local<Object> wrapper;
  GumV8Core * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cmodule_construct)
static gboolean gum_add_csymbol (const GumCSymbolDetails * details,
    GumAddCSymbolsContext * ctx);
GUMJS_DECLARE_FUNCTION (gumjs_cmodule_dispose)

static GumCModuleEntry * gum_cmodule_entry_new (Local<Object> wrapper,
    Local<Object> symbols, GumCModule * handle, GumV8CModule * module);
static void gum_cmodule_entry_free (GumCModuleEntry * self);
static void gum_cmodule_entry_on_weak_notify (
    const WeakCallbackInfo<GumCModuleEntry> & info);

static const GumV8Function gumjs_cmodule_functions[] =
{
  { "dispose", gumjs_cmodule_dispose },

  { NULL, NULL }
};

void
_gum_v8_cmodule_init (GumV8CModule * self,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto cmodule = _gum_v8_create_class ("CModule", gumjs_cmodule_construct,
      scope, module, isolate);
  _gum_v8_class_add (cmodule, gumjs_cmodule_functions, module, isolate);
}

void
_gum_v8_cmodule_realize (GumV8CModule * self)
{
  self->cmodules = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_cmodule_entry_free);
}

void
_gum_v8_cmodule_dispose (GumV8CModule * self)
{
  g_hash_table_remove_all (self->cmodules);
}

void
_gum_v8_cmodule_finalize (GumV8CModule * self)
{
  g_clear_pointer (&self->cmodules, g_hash_table_unref);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cmodule_construct)
{
  Local<Context> context = isolate->GetCurrentContext ();

  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new CModule()` to create a new instance");
    return;
  }

  gchar * source;
  Local<Object> symbols;
  gchar * toolchain = NULL;
  if (!_gum_v8_args_parse (args, "s|O?s?", &source, &symbols, &toolchain))
    return;

  GError * error = NULL;
  auto handle = gum_cmodule_new (toolchain, source, &error);

  g_free (source);
  g_free (toolchain);

  if (error == NULL && !symbols.IsEmpty ())
  {
    gboolean valid = TRUE;

    Local<Array> names;
    if (symbols->GetOwnPropertyNames (context).ToLocal (&names))
    {
      guint count = names->Length ();
      for (guint i = 0; i != count; i++)
      {
        Local<Value> name_val;
        if (!names->Get (context, i).ToLocal (&name_val))
        {
          valid = FALSE;
          break;
        }

        Local<String> name_str;
        if (!name_val->ToString (context).ToLocal (&name_str))
        {
          valid = FALSE;
          break;
        }

        String::Utf8Value name_utf8 (isolate, name_str);

        Local<Value> value_val;
        if (!symbols->Get (context, name_val).ToLocal (&value_val))
        {
          valid = FALSE;
          break;
        }

        gpointer value;
        if (!_gum_v8_native_pointer_get (value_val, &value, core))
        {
          valid = FALSE;
          break;
        }

        gum_cmodule_add_symbol (handle, *name_utf8, value);
      }
    }
    else
    {
      valid = FALSE;
    }

    if (!valid)
    {
      g_object_unref (handle);
      return;
    }
  }

  if (error == NULL)
    gum_cmodule_link (handle, &error);

  if (_gum_v8_maybe_throw (isolate, &error))
  {
    g_object_unref (handle);
    return;
  }

  GumAddCSymbolsContext ctx;
  ctx.wrapper = wrapper;
  ctx.core = core;

  gum_cmodule_enumerate_symbols (handle, (GumFoundCSymbolFunc) gum_add_csymbol,
      &ctx);

  gum_cmodule_drop_metadata (handle);

  auto entry = gum_cmodule_entry_new (wrapper, symbols, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, entry);
}

static gboolean
gum_add_csymbol (const GumCSymbolDetails * details,
                 GumAddCSymbolsContext * ctx)
{
  _gum_v8_object_set_pointer (ctx->wrapper, details->name,
      details->address, ctx->core);

  return TRUE;
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_cmodule_dispose, GumCModuleEntry)
{
  if (self != NULL)
  {
    wrapper->SetAlignedPointerInInternalField (0, NULL);

    g_hash_table_remove (module->cmodules, self);
  }
}

static GumCModuleEntry *
gum_cmodule_entry_new (Local<Object> wrapper,
                       Local<Object> symbols,
                       GumCModule * handle,
                       GumV8CModule * module)
{
  auto isolate = module->core->isolate;
  const GumMemoryRange * range;

  auto entry = g_slice_new (GumCModuleEntry);
  entry->wrapper = new GumPersistent<Object>::type (isolate, wrapper);
  entry->wrapper->SetWeak (entry, gum_cmodule_entry_on_weak_notify,
      WeakCallbackType::kParameter);
  entry->symbols = new GumPersistent<Object>::type (isolate, symbols);
  entry->handle = handle;
  entry->module = module;

  range = gum_cmodule_get_range (handle);
  module->core->isolate->AdjustAmountOfExternalAllocatedMemory (range->size);

  g_hash_table_add (module->cmodules, entry);

  return entry;
}

static void
gum_cmodule_entry_free (GumCModuleEntry * self)
{
  const GumMemoryRange * range;

  range = gum_cmodule_get_range (self->handle);
  self->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -((gssize) range->size));

  g_object_unref (self->handle);

  delete self->symbols;
  delete self->wrapper;

  g_slice_free (GumCModuleEntry, self);
}

static void
gum_cmodule_entry_on_weak_notify (
    const WeakCallbackInfo<GumCModuleEntry> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->cmodules, self);
}
