/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 DaVinci <nstefanclaudel13@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickthread.h"

#include "gumquickmacros.h"

enum _GumBacktracerType
{
  GUM_BACKTRACER_ACCURATE = 1,
  GUM_BACKTRACER_FUZZY = 2
};

GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

static const JSCFunctionListEntry gumjs_thread_entries[] =
{
  JS_CFUNC_DEF ("_backtrace", 0, gumjs_thread_backtrace),
  JS_CFUNC_DEF ("sleep", 0, gumjs_thread_sleep),
};

static const JSCFunctionListEntry gumjs_backtracer_entries[] =
{
  JS_PROP_INT32_DEF ("ACCURATE", GUM_BACKTRACER_ACCURATE, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("FUZZY", GUM_BACKTRACER_FUZZY, JS_PROP_C_W_E),
};

void
_gum_quick_thread_init (GumQuickThread * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj;

  self->core = core;

  _gum_quick_core_store_module_data (core, "thread", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_thread_entries,
      G_N_ELEMENTS (gumjs_thread_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Thread", obj, JS_PROP_C_W_E);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_backtracer_entries,
      G_N_ELEMENTS (gumjs_backtracer_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Backtracer", obj, JS_PROP_C_W_E);
}

void
_gum_quick_thread_dispose (GumQuickThread * self)
{
}

void
_gum_quick_thread_finalize (GumQuickThread * self)
{
  g_clear_pointer (&self->accurate_backtracer, g_object_unref);
  g_clear_pointer (&self->fuzzy_backtracer, g_object_unref);
}

static GumQuickThread *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "thread");
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  JSValue result;
  GumQuickThread * self;
  GumCpuContext * cpu_context;
  gint type;
  guint limit;
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs;
  guint i;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "C?iu", &cpu_context, &type, &limit))
    return JS_EXCEPTION;

  if (type != GUM_BACKTRACER_ACCURATE && type != GUM_BACKTRACER_FUZZY)
    goto invalid_type;

  if (type == GUM_BACKTRACER_ACCURATE)
  {
    if (self->accurate_backtracer == NULL)
      self->accurate_backtracer = gum_backtracer_make_accurate ();
    backtracer = self->accurate_backtracer;
  }
  else
  {
    if (self->fuzzy_backtracer == NULL)
      self->fuzzy_backtracer = gum_backtracer_make_fuzzy ();
    backtracer = self->fuzzy_backtracer;
  }
  if (backtracer == NULL)
    goto not_available;

  if (limit != 0)
  {
    gum_backtracer_generate_with_limit (backtracer, cpu_context, &ret_addrs,
        limit);
  }
  else
  {
    gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);
  }

  result = JS_NewArray (ctx);

  for (i = 0; i != ret_addrs.len; i++)
  {
    JS_DefinePropertyValueUint32 (ctx, result, i,
        _gum_quick_native_pointer_new (ctx, ret_addrs.items[i], core),
        JS_PROP_C_W_E);
  }

  return result;

invalid_type:
  {
    return _gum_quick_throw_literal (ctx, "invalid backtracer enum value");
  }
not_available:
  {
    return _gum_quick_throw_literal (ctx, (type == GUM_BACKTRACER_ACCURATE)
        ? "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.FUZZY)"
        : "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.ACCURATE)");
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gdouble delay;

  if (!_gum_quick_args_parse (args, "n", &delay))
    return JS_EXCEPTION;

  if (delay < 0)
    return JS_UNDEFINED;

  _gum_quick_scope_suspend (&scope);

  g_usleep ((gulong) (delay * G_USEC_PER_SEC));

  _gum_quick_scope_resume (&scope);

  return JS_UNDEFINED;
}
