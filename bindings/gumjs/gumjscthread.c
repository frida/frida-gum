/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscthread.h"

#include "gumjscmacros.h"

enum _GumBacktracerType
{
  GUM_BACKTRACER_ACCURATE = 1,
  GUM_BACKTRACER_FUZZY = 2
};

GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

static const JSStaticFunction gumjs_thread_functions[] =
{
  { "backtrace", gumjs_thread_backtrace, GUMJS_RO },
  { "sleep", gumjs_thread_sleep, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_jsc_thread_init (GumJscThread * self,
                      GumJscCore * core,
                      JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef thread;
  JSObjectRef backtracer;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Thread";
  def.staticFunctions = gumjs_thread_functions;
  klass = JSClassCreate (&def);
  thread = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, thread);

  backtracer = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_uint (ctx, backtracer, "ACCURATE", GUM_BACKTRACER_ACCURATE);
  _gumjs_object_set_uint (ctx, backtracer, "FUZZY", GUM_BACKTRACER_FUZZY);
  _gumjs_object_set (ctx, scope, "Backtracer", backtracer);
}

void
_gum_jsc_thread_dispose (GumJscThread * self)
{
  (void) self;
}

void
_gum_jsc_thread_finalize (GumJscThread * self)
{
  g_clear_pointer (&self->accurate_backtracer, g_object_unref);
  g_clear_pointer (&self->fuzzy_backtracer , g_object_unref);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  GumJscThread * self;
  GumJscCore * core;
  GumCpuContext * cpu_context = NULL;
  gint selector = GUM_BACKTRACER_ACCURATE;
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs;
  JSValueRef ret_addrs_js[G_N_ELEMENTS (ret_addrs.items)];
  guint i;

  self = JSObjectGetPrivate (this_object);
  core = self->core;

  if (!_gumjs_args_parse (args, "|C?i", &cpu_context, &selector))
    return NULL;
  if (selector != GUM_BACKTRACER_ACCURATE && selector != GUM_BACKTRACER_FUZZY)
    goto invalid_selector;

  if (selector == GUM_BACKTRACER_ACCURATE)
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

  gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);

  for (i = 0; i != ret_addrs.len; i++)
    ret_addrs_js[i] = _gumjs_native_pointer_new (ctx, ret_addrs.items[i], core);
  return JSObjectMakeArray (ctx, ret_addrs.len, ret_addrs_js, exception);

invalid_selector:
  {
    _gumjs_throw (ctx, exception, "invalid backtracer enum value");
    return NULL;
  }
not_available:
  {
    _gumjs_throw (ctx, exception, (selector == GUM_BACKTRACER_ACCURATE)
        ? "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.FUZZY)"
        : "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.ACCURATE)");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  gdouble delay;
  GumJscYield yield;

  if (!_gumjs_args_parse (args, "n", &delay))
    return NULL;
  if (delay < 0)
    goto beach;

  _gum_jsc_yield_begin (&yield, args->core);
  g_usleep (delay * G_USEC_PER_SEC);
  _gum_jsc_yield_end (&yield);

beach:
  return JSValueMakeUndefined (ctx);
}
