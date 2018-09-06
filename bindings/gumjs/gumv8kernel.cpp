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

struct GumKernelScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumPersistent<Function>::type * on_match;
  GumPersistent<Function>::type * on_error;
  GumPersistent<Function>::type * on_complete;

  GumV8Core * core;
};

struct GumKernelScanSyncContext
{
  Local<Array> matches;

  GumV8Core * core;
};

GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_base)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumV8MatchContext * mc);
static Local<Object> gum_parse_module_details (
    const GumModuleDetails * details, GumV8Core * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
static gboolean gum_emit_module_range (
    const GumKernelModuleRangeDetails * details, GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_protect)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_read_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_write_byte_array)

GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan)
static void gum_kernel_scan_context_free (GumKernelScanContext * self);
static void gum_kernel_scan_context_run (GumKernelScanContext * self);
static gboolean gum_kernel_scan_context_emit_match (GumAddress address,
    gsize size, GumKernelScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumKernelScanSyncContext * ctx);

static gboolean gum_v8_kernel_check_api_available (Isolate * isolate);

static const GumV8Property gumjs_kernel_values[] =
{
  { "available", gumjs_kernel_get_available, NULL },
  { "base", gumjs_kernel_get_base, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_kernel_functions[] =
{
  { "enumerateModules", gumjs_kernel_enumerate_modules },
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges },
  { "enumerateModuleRanges", gumjs_kernel_enumerate_module_ranges },
  { "alloc", gumjs_kernel_alloc },
  { "protect", gumjs_kernel_protect },
  { "readByteArray", gumjs_kernel_read_byte_array },
  { "writeByteArray", gumjs_kernel_write_byte_array },

  { "scan", gumjs_kernel_scan },
  { "scanSync", gumjs_kernel_scan_sync },

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

GUMJS_DEFINE_GETTER (gumjs_kernel_get_base)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address = gum_kernel_find_base_address ();
  info.GetReturnValue ().Set (_gum_v8_uint64_new (address, core));
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_modules)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_kernel_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto module = gum_parse_module_details (details, core);

  Handle<Value> argv[] = { module };
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

static Local<Object>
gum_parse_module_details (const GumModuleDetails * details,
                          GumV8Core * core)
{
  auto module = Object::New (core->isolate);
  _gum_v8_object_set_utf8 (module, "name", details->name, core);
  _gum_v8_object_set_uint64 (module, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (module, "size", details->range->size, core);
  return module;
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
  _gum_v8_object_set_uint64 (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->prot, core);

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

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumV8MatchContext mc;
  gchar * module_name;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "s?mF{onMatch,onComplete}", &module_name,
      &prot, &mc.on_match, &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_kernel_enumerate_module_ranges (
    (module_name == NULL) ? "Kernel" : module_name, prot,
    (GumFoundKernelModuleRangeFunc) gum_emit_module_range, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_module_range (const GumKernelModuleRangeDetails * details,
                       GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_utf8 (range, "name", details->name, core);
  _gum_v8_object_set_uint64 (range, "address", details->address, core);
  _gum_v8_object_set_uint (range, "size", details->size, core);
  _gum_v8_object_set_page_protection (range, "protection",
    details->protection, core);

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

  GumAddress address = gum_kernel_alloc_n_pages (n_pages);
  info.GetReturnValue ().Set (_gum_v8_uint64_new (address, core));
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_protect)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address;
  gsize size;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "QZm", &address, &size, &prot))
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

  GumAddress address;
  gssize length;
  if (!_gum_v8_args_parse (args, "QZ", &address, &length))
    return;

  if (address == 0)
  {
    info.GetReturnValue ().Set (Null (isolate));
    return;
  }

  Local<Value> result;
  if (length > 0)
  {
    gsize n_bytes_read;
    auto data = gum_kernel_read (address, length, &n_bytes_read);
    if (data != NULL)
    {
      result = ArrayBuffer::New (isolate, data, n_bytes_read,
          ArrayBufferCreationMode::kInternalized);
    }
    else
    {
      _gum_v8_throw_ascii (isolate,
          "access violation reading 0x%" G_GINT64_MODIFIER "x",
          address);
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

  GumAddress address;
  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "QB", &address, &bytes))
    return;

  gsize length;
  auto data = (const guint8 *) g_bytes_get_data (bytes, &length);

  if (!gum_kernel_write (address, data, length))
  {
    _gum_v8_throw_ascii (isolate,
        "access violation writing to 0x%" G_GINT64_MODIFIER "x",
        address);
  }

  g_bytes_unref (bytes);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan)
{
  GumAddress address;
  gsize size;
  gchar * match_str;
  Local<Function> on_match, on_error, on_complete;
  if (!_gum_v8_args_parse (args, "QZsF{onMatch,onError?,onComplete}",
      &address, &size, &match_str, &on_match, &on_error, &on_complete))
    return;

  GumMemoryRange range;
  range.base_address = address;
  range.size = size;

  auto pattern = gum_match_pattern_new_from_string (match_str);

  g_free (match_str);

  if (pattern != NULL)
  {
    auto ctx = g_slice_new0 (GumKernelScanContext);
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = new GumPersistent<Function>::type (isolate, on_match);
    if (!on_error.IsEmpty ())
      ctx->on_error = new GumPersistent<Function>::type (isolate, on_error);
    ctx->on_complete = new GumPersistent<Function>::type (isolate, on_complete);
    ctx->core = core;

    _gum_v8_core_pin (core);
    _gum_v8_core_push_job (core, (GumScriptJobFunc) gum_kernel_scan_context_run,
        ctx, (GDestroyNotify) gum_kernel_scan_context_free);
  }
  else
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid match pattern");
  }
}

static void
gum_kernel_scan_context_free (GumKernelScanContext * self)
{
  auto core = self->core;

  gum_match_pattern_free (self->pattern);

  {
    ScriptScope script_scope (core->script);

    delete self->on_match;
    delete self->on_error;
    delete self->on_complete;

    _gum_v8_core_unpin (core);
  }

  g_slice_free (GumKernelScanContext, self);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_kernel_scan_context_run (GumKernelScanContext * self)
{
  auto core = self->core;
  auto exceptor = core->exceptor;
  auto isolate = core->isolate;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    gum_kernel_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_kernel_scan_context_emit_match, self);
  }

  if (gum_exceptor_catch (exceptor, &scope) && self->on_error != nullptr)
  {
    ScriptScope script_scope (core->script);

    auto message = gum_exception_details_to_string (&scope.exception);

    auto on_error = Local<Function>::New (isolate, *self->on_error);
    Handle<Value> argv[] = { String::NewFromUtf8 (isolate, message) };
    on_error->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

    g_free (message);
  }

  {
    ScriptScope script_scope (core->script);

    auto on_complete (Local<Function>::New (isolate, *self->on_complete));
    on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_kernel_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumKernelScanContext * self)
{
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;

  auto on_match = Local<Function>::New (isolate, *self->on_match);
  Handle<Value> argv[] = {
    _gum_v8_uint64_new (address, self->core),
    Integer::NewFromUnsigned (isolate, size)
  };
  auto result = on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

/*
 * Prototype:
 * Kernel.scanSync(address, size, match_str)
 *
 * Docs:
 * Scans a kernel memory region for a specific string
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan_sync)
{
  GumAddress address;
  gsize size;
  gchar * match_str;
  if (!_gum_v8_args_parse (args, "QZs", &address, &size, &match_str))
    return;

  GumMemoryRange range;
  range.base_address = address;
  range.size = size;

  auto pattern = gum_match_pattern_new_from_string (match_str);

  g_free (match_str);

  if (pattern == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid match pattern");
    return;
  }

  GumKernelScanSyncContext ctx;
  ctx.matches = Array::New (isolate);
  ctx.core = core;

  GumExceptorScope scope;

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    gum_kernel_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        &ctx);
  }

  gum_match_pattern_free (pattern);

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
  else
  {
    info.GetReturnValue ().Set (ctx.matches);
  }
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumKernelScanSyncContext * ctx)
{
  GumV8Core * core = ctx->core;

  auto match = Object::New (core->isolate);
  _gum_v8_object_set_uint64 (match, "address", address, core);
  _gum_v8_object_set_uint (match, "size", size, core);
  ctx->matches->Set (core->isolate->GetCurrentContext (),
      ctx->matches->Length (), match).ToChecked ();

  return TRUE;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

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
