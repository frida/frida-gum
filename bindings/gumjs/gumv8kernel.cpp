/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8kernel.h"

#include "gumv8macros.h"

#include <gum/gumkernel.h>
#include <string.h>

#define GUMJS_MODULE_NAME Kernel

using namespace v8;

struct GumV8MatchContext
{
  Local<Function> on_match;
  Local<Function> on_complete;

  GumV8Core * core;

  gboolean has_pending_exception;
};

GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_protect)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_read_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_write_byte_array)

static gboolean gum_v8_kernel_check_api_available (Isolate * isolate);

static const GumV8Property gumjs_kernel_values[] =
{
  { "available", gumjs_kernel_get_available, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_kernel_functions[] =
{
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges },
  { "alloc", gumjs_kernel_alloc },
  { "protect", gumjs_kernel_protect },
  { "readByteArray", gumjs_kernel_read_byte_array },
  { "writeByteArray", gumjs_kernel_write_byte_array },

  { NULL, NULL }
};

void
_gum_v8_kernel_init (GumV8Kernel * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto kernel = _gum_v8_create_module ("Kernel", scope, isolate);
  kernel->Set (_gum_v8_string_new_ascii (isolate, "pageSize"),
      Number::New (isolate, gum_kernel_query_page_size ()), ReadOnly);
  _gum_v8_module_add (module, kernel, gumjs_kernel_values, isolate);
  _gum_v8_module_add (module, kernel, gumjs_kernel_functions, isolate);
}

void
_gum_v8_kernel_realize (GumV8Kernel * self)
{
}

void
_gum_v8_kernel_dispose (GumV8Kernel * self)
{
}

void
_gum_v8_kernel_finalize (GumV8Kernel * self)
{
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_available)
{
  info.GetReturnValue ().Set (!!gum_kernel_api_is_available ());
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_ranges)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumV8MatchContext mc;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_kernel_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->prot, core);

  auto f = details->file;
  if (f != NULL)
  {
    Local<Object> file (Object::New (isolate));
    _gum_v8_object_set_utf8 (range, "path", f->path, core);
    _gum_v8_object_set_uint (range, "offset", f->offset, core);
    _gum_v8_object_set (range, "file", file, core);
  }

  Handle<Value> argv[] = { range };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_alloc)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gsize size;
  if (!_gum_v8_args_parse (args, "Z", &size))
    return;

  if (size == 0 || size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  gsize page_size = gum_kernel_query_page_size ();
  guint n_pages = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

  gpointer address = gum_kernel_alloc_n_pages (n_pages);
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (address, core));
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_protect)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gpointer address;
  gsize size;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "pZm", &address, &size, &prot))
    return;

  if (size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  bool success;
  if (size != 0)
    success = !!gum_kernel_try_mprotect (address, size, prot);
  else
    success = true;

  info.GetReturnValue ().Set (success);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_byte_array)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gpointer address;
  gssize length;
  if (!_gum_v8_args_parse (args, "pZ", &address, &length))
    return;

  if (address == NULL)
  {
    info.GetReturnValue ().Set (Null (isolate));
    return;
  }

  Local<Value> result;
  if (length > 0)
  {
    gsize n_bytes_read;
    auto data = gum_kernel_read (GUM_ADDRESS (address), length, &n_bytes_read);
    if (data != NULL)
    {
      result = ArrayBuffer::New (isolate, data, n_bytes_read,
          ArrayBufferCreationMode::kInternalized);
    }
    else
    {
      _gum_v8_throw_ascii (isolate,
          "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (address));
      return;
    }
  }
  else
  {
    result = ArrayBuffer::New (isolate, 0);
  }

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_write_byte_array)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gpointer address;
  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "pB", &address, &bytes))
    return;

  gsize length;
  auto data = (const guint8 *) g_bytes_get_data (bytes, &length);

  if (!gum_kernel_write (GUM_ADDRESS (address), data, length))
  {
    _gum_v8_throw_ascii (isolate,
        "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (address));
  }

  g_bytes_unref (bytes);
}

static gboolean
gum_v8_kernel_check_api_available (Isolate * isolate)
{
  if (!gum_kernel_api_is_available ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "Kernel API is not available on this system");
    return FALSE;
  }

  return TRUE;
}
