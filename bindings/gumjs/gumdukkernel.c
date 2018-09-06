/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukkernel.h"

#include "gumdukmacros.h"

typedef struct _GumDukMatchContext GumDukMatchContext;
typedef struct _GumKernelScanContext GumKernelScanContext;

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

struct _GumKernelScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_error;
  GumDukHeapPtr on_complete;

  GumDukCore * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_kernel_construct)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_base)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumDukMatchContext * mc);
static void gum_push_module (duk_context * ctx,
    const GumModuleDetails * details, GumDukCore * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumDukMatchContext * mc);
static void gum_push_range (duk_context * ctx,
    const GumRangeDetails * details, GumDukCore * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
static gboolean gum_emit_module_range (
    const GumKernelModuleRangeDetails * details, GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_protect)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_read_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_write_byte_array)

GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan)
static void gum_kernel_scan_context_free (GumKernelScanContext * ctx);
static void gum_kernel_scan_context_run (GumKernelScanContext * self);
static gboolean gum_kernel_scan_context_emit_match (GumAddress address,
    gsize size, GumKernelScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumDukCore * core);

static void gum_duk_kernel_check_api_available (duk_context * ctx);

static const GumDukPropertyEntry gumjs_kernel_values[] =
{
  { "available", gumjs_kernel_get_available, NULL },
  { "base", gumjs_kernel_get_base, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_kernel_functions[] =
{
  { "enumerateModules", gumjs_kernel_enumerate_modules, 1 },
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges, 2 },
  { "enumerateModuleRanges", gumjs_kernel_enumerate_module_ranges, 3 },
  { "alloc", gumjs_kernel_alloc, 2 },
  { "protect", gumjs_kernel_protect, 3 },
  { "readByteArray", gumjs_kernel_read_byte_array, 2 },
  { "writeByteArray", gumjs_kernel_write_byte_array, 2 },

  { "scan", gumjs_kernel_scan, 4 },
  { "scanSync", gumjs_kernel_scan_sync, 3 },

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
  duk_push_uint (ctx, gum_kernel_query_page_size ());
  duk_put_prop_string (ctx, -2, "pageSize");
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
}

void
_gum_duk_kernel_finalize (GumDukKernel * self)
{
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_kernel_construct)
{
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_available)
{
  duk_push_boolean (ctx, gum_kernel_api_is_available ());
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_base)
{
  GumAddress address;
  GumDukCore * core = args->core;

  gum_duk_kernel_check_api_available (ctx);

  address = gum_kernel_find_base_address ();
  _gum_duk_push_uint64 (ctx, address, core);

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_modules)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_kernel_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);
  gum_push_module (ctx, details, scope->core);

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

static void
gum_push_module (duk_context * ctx,
                 const GumModuleDetails * details,
                 GumDukCore * core)
{
  duk_push_object (ctx);

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_uint64 (ctx, details->range->base_address, core);
  duk_put_prop_string (ctx, -2, "base");

  duk_push_uint (ctx, details->range->size);
  duk_put_prop_string (ctx, -2, "size");
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
  gum_push_range (ctx, details, scope->core);

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

static void
gum_push_range (duk_context * ctx,
                const GumRangeDetails * details,
                GumDukCore * core)
{
  duk_push_object (ctx);

  _gum_duk_push_uint64 (ctx, details->range->base_address, core);
  duk_put_prop_string (ctx, -2, "base");

  duk_push_uint (ctx, details->range->size);
  duk_put_prop_string (ctx, -2, "size");

  _gum_duk_push_page_protection (ctx, details->prot);
  duk_put_prop_string (ctx, -2, "protection");
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
{
  gchar * module_name;
  GumDukMatchContext mc;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "s?mF{onMatch,onComplete}", &module_name, &prot,
      &mc.on_match, &mc.on_complete);
  mc.scope = &scope;

  gum_kernel_enumerate_module_ranges (
      (module_name == NULL) ? "Kernel" : module_name, prot,
      (GumFoundKernelModuleRangeFunc) gum_emit_module_range, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_module_range (const GumKernelModuleRangeDetails * details,
                       GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_uint64 (ctx, details->address, scope->core);
  duk_put_prop_string (ctx, -2, "address");

  duk_push_uint (ctx, details->size);
  duk_put_prop_string (ctx, -2, "size");

  _gum_duk_push_page_protection (ctx, details->protection);
  duk_put_prop_string (ctx, -2, "protection");

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

GUMJS_DEFINE_FUNCTION (gumjs_kernel_alloc)
{
  GumAddress address;
  gsize size, page_size;
  guint n_pages;
  GumDukCore * core = args->core;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "Z", &size);

  if (size == 0 || size > 0x7fffffff)
    _gum_duk_throw (ctx, "invalid size");

  page_size = gum_kernel_query_page_size ();
  n_pages = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

  address = gum_kernel_alloc_n_pages (n_pages);
  _gum_duk_push_uint64 (ctx, address, core);

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_protect)
{
  GumAddress address;
  gsize size;
  GumPageProtection prot;
  gboolean success;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "QZm", &address, &size, &prot);

  if (size > 0x7fffffff)
    _gum_duk_throw (ctx, "invalid size");

  if (size != 0)
    success = gum_kernel_try_mprotect (address, size, prot);
  else
    success = TRUE;

  duk_push_boolean (ctx, success);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_byte_array)
{
  GumAddress address;
  gssize length;
  gsize n_bytes_read;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "QZ", &address, &length);

  if (address == 0)
  {
    duk_push_null (ctx);
    return 1;
  }

  if (length > 0)
  {
    guint8 * data;
    gpointer buffer_data;

    data = gum_kernel_read (address, length, &n_bytes_read);
    if (data == NULL)
    {
      _gum_duk_throw (ctx, "access violation reading 0x%" G_GINT64_MODIFIER "x",
          address);
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
  GumAddress address;
  GBytes * bytes;
  const guint8 * data;
  gsize length;
  gboolean success;

  gum_duk_kernel_check_api_available (ctx);

  _gum_duk_args_parse (args, "QB", &address, &bytes);

  data = g_bytes_get_data (bytes, &length);
  success = gum_kernel_write (address, data, length);

  g_bytes_unref (bytes);

  if (!success)
  {
    _gum_duk_throw (ctx, "access violation writing to 0x%" G_GINT64_MODIFIER "x",
        address);
  }

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan)
{
  GumDukCore * core = args->core;
  GumKernelScanContext sc;
  GumAddress address;
  gsize size;
  const gchar * match_str;

  _gum_duk_args_parse (args, "QZsF{onMatch,onError?,onComplete}",
      &address, &size, &match_str, &sc.on_match, &sc.on_error, &sc.on_complete);

  sc.range.base_address = address;
  sc.range.size = size;
  sc.pattern = gum_match_pattern_new_from_string (match_str);
  sc.core = core;

  if (sc.pattern == NULL)
    _gum_duk_throw (ctx, "invalid match pattern");

  _gum_duk_protect (ctx, sc.on_match);
  if (sc.on_error != NULL)
    _gum_duk_protect (ctx, sc.on_error);
  _gum_duk_protect (ctx, sc.on_complete);

  _gum_duk_core_pin (core);
  _gum_duk_core_push_job (core,
      (GumScriptJobFunc) gum_kernel_scan_context_run,
      g_slice_dup (GumKernelScanContext, &sc),
      (GDestroyNotify) gum_kernel_scan_context_free);

  return 0;
}

static void
gum_kernel_scan_context_free (GumKernelScanContext * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_unprotect (ctx, self->on_match);
  if (self->on_error != NULL)
    _gum_duk_unprotect (ctx, self->on_error);
  _gum_duk_unprotect (ctx, self->on_complete);

  _gum_duk_core_unpin (core);
  _gum_duk_scope_leave (&scope);

  gum_match_pattern_free (self->pattern);

  g_slice_free (GumKernelScanContext, self);
}

static void
gum_kernel_scan_context_run (GumKernelScanContext * self)
{
  GumDukCore * core = self->core;
  GumDukScope script_scope;
  duk_context * ctx;

  gum_kernel_scan (&self->range, self->pattern,
      (GumMemoryScanMatchFunc) gum_kernel_scan_context_emit_match, self);

  ctx = _gum_duk_scope_enter (&script_scope, core);

  duk_push_heapptr (ctx, self->on_complete);
  _gum_duk_scope_call (&script_scope, 0);
  duk_pop (ctx);

  _gum_duk_scope_leave (&script_scope);
}

static gboolean
gum_kernel_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumKernelScanContext * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;
  gboolean proceed;

  ctx = _gum_duk_scope_enter (&scope, core);

  duk_push_heapptr (ctx, self->on_match);

  _gum_duk_push_uint64 (ctx, address, core);
  duk_push_number (ctx, size);

  proceed = TRUE;

  if (_gum_duk_scope_call (&scope, 2))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan_sync)
{
  GumDukCore * core = args->core;
  GumAddress address;
  gsize size;
  const gchar * match_str;
  GumMemoryRange range;
  GumMatchPattern * pattern;

  _gum_duk_args_parse (args, "QZs", &address, &size, &match_str);

  range.base_address = address;
  range.size = size;

  pattern = gum_match_pattern_new_from_string (match_str);
  if (pattern == NULL)
    _gum_duk_throw (ctx, "invalid match pattern");

  duk_push_array (ctx);

  gum_kernel_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
      core);

  gum_match_pattern_free (pattern);

  return 1;
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  duk_push_object (ctx);

  _gum_duk_push_uint64 (ctx, address, core);
  duk_put_prop_string (ctx, -2, "address");

  duk_push_uint (ctx, size);
  duk_put_prop_string (ctx, -2, "size");

  duk_put_prop_index (ctx, -2, (duk_uarridx_t) duk_get_length (ctx, -2));

  return TRUE;
}

static void
gum_duk_kernel_check_api_available (duk_context * ctx)
{
  if (!gum_kernel_api_is_available ())
    _gum_duk_throw (ctx, "Kernel API is not available on this system");
}
