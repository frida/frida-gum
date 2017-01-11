/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukkernel.h"

#include "gumdukmacros.h"

typedef struct _GumDukMatchContext GumDukMatchContext;

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_kernel_construct)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_read_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_write_byte_array)

static void gum_duk_kernel_check_api_available (duk_context * ctx);

static const GumDukPropertyEntry gumjs_kernel_values[] =
{
  { "available", gumjs_kernel_get_available, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_kernel_functions[] =
{
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges, 2 },
  { "readByteArray", gumjs_kernel_read_byte_array, 2 },
  { "writeByteArray", gumjs_kernel_write_byte_array, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_kernel_init (GumDukKernel * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_kernel_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_kernel_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_kernel_values);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "Kernel");
}

void
_gum_duk_kernel_dispose (GumDukKernel * self)
{
  (void) self;
}

void
_gum_duk_kernel_finalize (GumDukKernel * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_kernel_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_available)
{
  (void) args;

  duk_push_boolean (ctx, gum_kernel_api_is_available ());
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_ranges)
{
  GumDukMatchContext mc;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_kernel_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);
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

GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_byte_array)
{
  gpointer address;
  gssize length;
  gsize n_bytes_read;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "pZ", &address, &length);

  if (address == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  if (length > 0)
  {
    guint8 * data;
    gpointer buffer_data;

    data = gum_kernel_read (GUM_ADDRESS (address), length, &n_bytes_read);
    if (data == NULL)
    {
      _gum_duk_throw (ctx, "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (address));
    }

    buffer_data = duk_push_fixed_buffer (ctx, n_bytes_read);
    memcpy (buffer_data, data, n_bytes_read);

    g_free (data);
  }
  else
  {
    n_bytes_read = 0;

    duk_push_fixed_buffer (ctx, 0);
  }

  duk_push_buffer_object (ctx, -1, 0, n_bytes_read, DUK_BUFOBJ_ARRAYBUFFER);

  duk_swap (ctx, -2, -1);
  duk_pop (ctx);

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_write_byte_array)
{
  gpointer address;
  GBytes * bytes;
  const guint8 * data;
  gsize length;
  gboolean success;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "pB", &address, &bytes);

  data = g_bytes_get_data (bytes, &length);
  success = gum_kernel_write (GUM_ADDRESS (address), data, length);

  g_bytes_unref (bytes);

  if (!success)
  {
    _gum_duk_throw (ctx, "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (address));
  }

  return 0;
}

static void
gum_duk_kernel_check_api_available (duk_context * ctx)
{
  if (!gum_kernel_api_is_available ())
    _gum_duk_throw (ctx, "Kernel API is not available on this system");
}
