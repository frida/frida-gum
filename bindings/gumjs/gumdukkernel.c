/*
 * Copyright (C) 2016-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukkernel.h"

#include "gumdukmacros.h"

typedef guint GumMemoryValueType;
typedef struct _GumDukMatchContext GumDukMatchContext;
typedef struct _GumKernelScanContext GumKernelScanContext;

enum _GumMemoryValueType
{
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_LONG,
  GUM_MEMORY_VALUE_ULONG,
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING
};

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

static int gum_duk_kernel_read (GumMemoryValueType type,
    const GumDukArgs * args);
static int gum_duk_kernel_write (GumMemoryValueType type,
    const GumDukArgs * args);

#define GUMJS_DEFINE_MEMORY_READ(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_##T) \
  { \
    return gum_duk_kernel_read (GUM_MEMORY_VALUE_##T, args); \
  }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_kernel_write_##T) \
  { \
    return gum_duk_kernel_write (GUM_MEMORY_VALUE_##T, args); \
  }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
  GUMJS_DEFINE_MEMORY_READ (T); \
  GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
  { "read" N, gumjs_kernel_read_##T, 2 }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
  { "write" N, gumjs_kernel_write_##T, 2 }
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
  GUMJS_EXPORT_MEMORY_READ (N, T), \
  GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUMJS_DEFINE_MEMORY_READ_WRITE (S8)
GUMJS_DEFINE_MEMORY_READ_WRITE (U8)
GUMJS_DEFINE_MEMORY_READ_WRITE (S16)
GUMJS_DEFINE_MEMORY_READ_WRITE (U16)
GUMJS_DEFINE_MEMORY_READ_WRITE (S32)
GUMJS_DEFINE_MEMORY_READ_WRITE (U32)
GUMJS_DEFINE_MEMORY_READ_WRITE (S64)
GUMJS_DEFINE_MEMORY_READ_WRITE (U64)
GUMJS_DEFINE_MEMORY_READ_WRITE (LONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (ULONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUMJS_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUMJS_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUMJS_DEFINE_MEMORY_READ (C_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)

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
  { "_enumerateModules", gumjs_kernel_enumerate_modules, 1 },
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges, 2 },
  { "_enumerateModuleRanges", gumjs_kernel_enumerate_module_ranges, 3 },
  { "alloc", gumjs_kernel_alloc, 2 },
  { "protect", gumjs_kernel_protect, 3 },

  GUMJS_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Short", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UShort", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Int", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UInt", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Long", LONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ULong", ULONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUMJS_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),

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

  duk_push_object (ctx);
  duk_push_uint (ctx, gum_kernel_query_page_size ());
  duk_put_prop_string (ctx, -2, "pageSize");
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_kernel_values);
  duk_put_function_list (ctx, -1, gumjs_kernel_functions);
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

static int
gum_duk_kernel_read (GumMemoryValueType type,
                     const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = args->core;
  GumAddress address;
  gssize length = 0;
  gsize n_bytes_read;

  gum_duk_kernel_check_api_available (ctx);

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      _gum_duk_args_parse (args, "QZ", &address, &length);
      break;
    default:
      _gum_duk_args_parse (args, "Q", &address);
      break;
  }

  if (address == 0)
  {
    duk_push_null (ctx);
    return 1;
  }

  if (length == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
      case GUM_MEMORY_VALUE_U8:
        length = 1;
        break;
      case GUM_MEMORY_VALUE_S16:
      case GUM_MEMORY_VALUE_U16:
        length = 2;
        break;
      case GUM_MEMORY_VALUE_S32:
      case GUM_MEMORY_VALUE_U32:
      case GUM_MEMORY_VALUE_FLOAT:
        length = 4;
        break;
      case GUM_MEMORY_VALUE_S64:
      case GUM_MEMORY_VALUE_U64:
      case GUM_MEMORY_VALUE_LONG:
      case GUM_MEMORY_VALUE_ULONG:
      case GUM_MEMORY_VALUE_DOUBLE:
        length = 8;
        break;
      default:
        break;
    }
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

    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
        duk_push_number (ctx, *((gint8 *) data));
        break;
      case GUM_MEMORY_VALUE_U8:
        duk_push_number (ctx, *((guint8 *) data));
        break;
      case GUM_MEMORY_VALUE_S16:
        duk_push_number (ctx, *((gint16 *) data));
        break;
      case GUM_MEMORY_VALUE_U16:
        duk_push_number (ctx, *((guint16 *) data));
        break;
      case GUM_MEMORY_VALUE_S32:
        duk_push_number (ctx, *((gint32 *) data));
        break;
      case GUM_MEMORY_VALUE_U32:
        duk_push_number (ctx, *((guint32 *) data));
        break;
      case GUM_MEMORY_VALUE_S64:
        _gum_duk_push_int64 (ctx, *((gint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        _gum_duk_push_uint64 (ctx, *((guint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        _gum_duk_push_int64 (ctx, *((glong *) data), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        _gum_duk_push_uint64 (ctx, *((gulong *) data), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        duk_push_number (ctx, *((gfloat *) data));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        duk_push_number (ctx, *((gdouble *) data));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        buffer_data = duk_push_fixed_buffer (ctx, n_bytes_read);
        memcpy (buffer_data, data, n_bytes_read);

        duk_push_buffer_object (ctx, -1, 0, n_bytes_read,
            DUK_BUFOBJ_ARRAYBUFFER);

        duk_swap (ctx, -2, -1);
        duk_pop (ctx);

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * str;

        str = g_utf8_make_valid ((gchar *) data, length);
        duk_push_string (ctx, str);
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const gchar * end;
        gchar * slice;

        if (!g_utf8_validate ((gchar *) data, length, &end))
        {
          _gum_duk_throw (ctx, "can't decode byte 0x%02x in position %u",
              (guint8) *end, (guint) (end - (gchar *) data));
        }

        slice = g_strndup ((gchar *) data, length);
        duk_push_string (ctx, slice);
        g_free (slice);

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gunichar2 * str_utf16;
        gchar * str_utf8;
        glong size;

        str_utf16 = (gunichar2 *) data;

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        if (str_utf8 == NULL)
          _gum_duk_throw (ctx, "invalid string");
        duk_push_string (ctx, str_utf8);
        g_free (str_utf8);

        break;
      }
      default:
        g_assert_not_reached ();
    }

    g_free (data);
  }
  else if (type == GUM_MEMORY_VALUE_BYTE_ARRAY)
  {
    duk_push_fixed_buffer (ctx, 0);
  }
  else
  {
    _gum_duk_throw (ctx, "please provide a length > 0");
  }

  return 1;
}

static int
gum_duk_kernel_write (GumMemoryValueType type,
                      const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumAddress address = 0;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  gfloat number32 = 0;
  GBytes * bytes = NULL;
  const gchar * str = NULL;
  gunichar2 * str_utf16 = NULL;
  const guint8 * data = NULL;
  gsize str_length = 0;
  gsize length = 0;
  gboolean success;

  gum_duk_kernel_check_api_available (ctx);

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      _gum_duk_args_parse (args, "Qz", &address, &s);
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      _gum_duk_args_parse (args, "QZ", &address, &u);
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      _gum_duk_args_parse (args, "Qq", &address, &s64);
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      _gum_duk_args_parse (args, "QQ", &address, &u64);
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      _gum_duk_args_parse (args, "Qn", &address, &number);
      number32 = (gfloat) number;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      _gum_duk_args_parse (args, "QB", &address, &bytes);
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      _gum_duk_args_parse (args, "Qs", &address, &str);

      str_length = g_utf8_strlen (str, -1);
      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);
      break;
    default:
      g_assert_not_reached ();
  }

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
      data = (guint8 *) &s;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_U8:
      data = (guint8 *) &u;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_S16:
      data = (guint8 *) &s;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_U16:
      data = (guint8 *) &u;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_S32:
      data = (guint8 *) &s;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_U32:
      data = (guint8 *) &u;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_LONG:
    case GUM_MEMORY_VALUE_S64:
      data = (guint8 *) &s64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_ULONG:
    case GUM_MEMORY_VALUE_U64:
      data = (guint8 *) &u64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
      data = (guint8 *) &number32;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_DOUBLE:
      data = (guint8 *) &number;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      data = g_bytes_get_data (bytes, &length);
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
      data = (guint8 *) str;
      length = g_utf8_offset_to_pointer (str, str_length) - str + 1;
      break;
    case GUM_MEMORY_VALUE_UTF16_STRING:
      data = (guint8 *) str_utf16;
      length = (str_length + 1) * sizeof (gunichar2);
      break;
    default:
      g_assert_not_reached ();
  }

  if (length <= 0)
    _gum_duk_throw (ctx, "please provide a length > 0");

  success = gum_kernel_write (address, data, length);

  g_bytes_unref (bytes);
  g_free (str_utf16);

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
