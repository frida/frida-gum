/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukthread.h"

#include "gumdukmacros.h"

enum _GumBacktracerType
{
  GUM_BACKTRACER_ACCURATE = 1,
  GUM_BACKTRACER_FUZZY = 2
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_thread_construct)
GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

static const duk_function_list_entry gumjs_thread_functions[] =
{
  { "backtrace", gumjs_thread_backtrace, 2 },
  { "sleep", gumjs_thread_sleep, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_thread_init (GumDukThread * self,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_thread_construct, 0);
  // [ newobj ]
  duk_push_object (ctx);
  // [ newobj newproto ]
  duk_put_function_list (ctx, -1, gumjs_thread_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ newobj ]
  duk_new (ctx, 0);
  // [ newinst ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Thread");
  // []

  duk_push_object (ctx);
  // [ newobj ]
  duk_push_uint (ctx, GUM_BACKTRACER_ACCURATE);
  // [ newobj GUM_BACKTRACER_ACCURATE ]
  duk_put_prop_string (ctx, -2, "ACCURATE");
  // [ newobj ]
  duk_push_uint (ctx, GUM_BACKTRACER_FUZZY);
  // [ newobj GUM_BACKTRACER_FUZZY ]
  duk_put_prop_string (ctx, -2, "FUZZY");
  // [ newobj ]
  duk_put_global_string (ctx, "Backtracer");
  //
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_thread_construct)
{
  return 0;
}

void
_gum_duk_thread_dispose (GumDukThread * self)
{
  (void) self;
}

void
_gum_duk_thread_finalize (GumDukThread * self)
{
  g_clear_pointer (&self->accurate_backtracer, g_object_unref);
  g_clear_pointer (&self->fuzzy_backtracer , g_object_unref);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  GumDukThread * self;
  GumDukCore * core;
  GumCpuContext * cpu_context = NULL;
  gint selector = GUM_BACKTRACER_ACCURATE;
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs;
  guint i;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  core = self->core;

  if (!_gumjs_args_parse (ctx, "|C?i", &cpu_context, &selector))
  {
    duk_push_null (ctx);
    return 1;
  }

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

  duk_push_array (ctx);
  // [ newarray ]
  for (i = 0; i != ret_addrs.len; i++)
  {
    _gumjs_native_pointer_push (ctx, ret_addrs.items[i], core);
    // [ newarray element ]
    duk_put_prop_index (ctx, -2, i);
    // [ newarray ]
  }

  return 1;

invalid_selector:
  {
    _gumjs_throw (ctx, "invalid backtracer enum value");
    {
      duk_push_null (ctx);
      return 1;
    }
  }
not_available:
  {
    _gumjs_throw (ctx, (selector == GUM_BACKTRACER_ACCURATE)
        ? "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.FUZZY)"
        : "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.ACCURATE)");
    {
      duk_push_null (ctx);
      return 1;
    }
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  GumDukCore * core = args->core;
  gdouble delay;

  _gumjs_args_parse (ctx, "n", &delay);

  if (delay < 0)
    return 0;

  GUM_DUK_CORE_UNLOCK (core);

  g_usleep (delay * G_USEC_PER_SEC);

  GUM_DUK_CORE_LOCK (core);

  return 0;
}
