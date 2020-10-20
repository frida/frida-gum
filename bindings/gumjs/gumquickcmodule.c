/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickcmodule.h"

#include "gumcmodule.h"
#include "gumquickmacros.h"

typedef struct _GumAddCSymbolsOperation GumAddCSymbolsOperation;

struct _GumAddCSymbolsOperation
{
  JSValue wrapper;
  GumQuickCore * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cmodule_construct)
static gboolean gum_add_csymbol (const GumCSymbolDetails * details,
    GumAddCSymbolsOperation * op);
GUMJS_DECLARE_FINALIZER (gumjs_cmodule_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_cmodule_dispose)

static const JSClassDef gumjs_cmodule_def =
{
  .class_name = "CModule",
  .finalizer = gumjs_cmodule_finalize,
};

static const JSCFunctionListEntry gumjs_cmodule_entries[] =
{
  JS_CFUNC_DEF ("dispose", 0, gumjs_cmodule_dispose),
};

void
_gum_quick_cmodule_init (GumQuickCModule * self,
                         JSValue ns,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  self->cmodules = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_cmodule_free);

  _gum_quick_core_store_module_data (core, "cmodule", self);

  _gum_quick_create_class (ctx, &gumjs_cmodule_def, core, &self->cmodule_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_cmodule_construct,
      gumjs_cmodule_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_cmodule_entries,
      G_N_ELEMENTS (gumjs_cmodule_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_cmodule_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_cmodule_dispose (GumQuickCModule * self)
{
  g_hash_table_remove_all (self->cmodules);
}

void
_gum_quick_cmodule_finalize (GumQuickCModule * self)
{
  g_clear_pointer (&self->cmodules, g_hash_table_unref);
}

static GumQuickCModule *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "cmodule");
}

static gboolean
gum_quick_cmodule_get (JSContext * ctx,
                       JSValueConst val,
                       GumQuickCore * core,
                       GumCModule ** cmodule)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->cmodule_class, core,
      (gpointer *) cmodule);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cmodule_construct)
{
  JSValue result;
  GumQuickCModule * parent;
  const gchar * source;
  JSValue symbols;
  JSValue proto;
  JSValue wrapper = JS_NULL;
  GumCModule * cmodule = NULL;
  GError * error;
  JSPropertyEnum * properties = NULL;
  uint32_t n = 0;
  uint32_t i;
  const char * name = NULL;
  JSValue val = JS_NULL;
  GumAddCSymbolsOperation add_op;

  parent = gumjs_get_parent_module (core);

  symbols = JS_NULL;
  if (!_gum_quick_args_parse (args, "s|O", &source, &symbols))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->cmodule_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  error = NULL;
  cmodule = gum_cmodule_new (source, &error);
  if (error != NULL)
    goto propagate_error;

  if (!JS_IsNull (symbols))
  {
    if (JS_GetOwnPropertyNames (ctx, &properties, &n, symbols,
        JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) != 0)
      goto propagate_exception;

    for (i = 0; i != n; i++)
    {
      JSAtom name_atom = properties[i].atom;
      gpointer v;

      name = JS_AtomToCString (ctx, name_atom);
      if (name == NULL)
        goto propagate_exception;

      val = JS_GetProperty (ctx, symbols, name_atom);
      if (JS_IsException (val))
        goto propagate_exception;

      if (!_gum_quick_native_pointer_get (ctx, val, core, &v))
        goto propagate_exception;

      gum_cmodule_add_symbol (cmodule, name, v);

      JS_FreeValue (ctx, val);
      val = JS_NULL;

      JS_FreeCString (ctx, name);
      name = NULL;
    }

    /* Anchor lifetime to CModule instance. */
    JS_DefinePropertyValue (ctx, wrapper,
        GUM_QUICK_CORE_ATOM (core, resource),
        JS_DupValue (ctx, symbols),
        0);
  }

  if (!gum_cmodule_link (cmodule, &error))
    goto propagate_error;

  add_op.wrapper = wrapper;
  add_op.core = core;
  gum_cmodule_enumerate_symbols (cmodule, (GumFoundCSymbolFunc) gum_add_csymbol,
      &add_op);

  gum_cmodule_drop_metadata (cmodule);

  g_hash_table_add (parent->cmodules, cmodule);

  JS_SetOpaque (wrapper, g_steal_pointer (&cmodule));

  result = wrapper;
  wrapper = JS_NULL;

  goto beach;

propagate_error:
  {
    _gum_quick_throw_error (ctx, &error);
    goto propagate_exception;
  }
propagate_exception:
  {
    result = JS_EXCEPTION;
    goto beach;
  }
beach:
  {
    JS_FreeValue (ctx, val);
    JS_FreeCString (ctx, name);

    for (i = 0; i != n; i++)
      JS_FreeAtom (ctx, properties[i].atom);
    js_free (ctx, properties);

    gum_cmodule_free (cmodule);

    JS_FreeValue (ctx, wrapper);

    return result;
  }
}

static gboolean
gum_add_csymbol (const GumCSymbolDetails * details,
                 GumAddCSymbolsOperation * op)
{
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;

  JS_DefinePropertyValueStr (ctx, op->wrapper,
      details->name,
      _gum_quick_native_pointer_new (ctx, details->address, core),
      JS_PROP_C_W_E);

  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_cmodule_finalize)
{
  GumQuickCModule * parent;
  GumCModule * m;

  parent = gumjs_get_parent_module (core);

  m = JS_GetOpaque (val, parent->cmodule_class);
  if (m == NULL)
    return;

  g_hash_table_remove (parent->cmodules, m);
}

GUMJS_DEFINE_FUNCTION (gumjs_cmodule_dispose)
{
  GumCModule * self;

  if (!gum_quick_cmodule_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self != NULL)
  {
    g_hash_table_remove (gumjs_get_parent_module (core)->cmodules, self);

    JS_SetOpaque (this_val, NULL);
  }

  return JS_UNDEFINED;
}
