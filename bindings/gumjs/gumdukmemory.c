/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukmemory.h"

#include "gumdukmacros.h"

#include <string.h>
#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

typedef guint GumMemoryValueType;
typedef struct _GumMemoryPatchContext GumMemoryPatchContext;
typedef struct _GumMemoryScanContext GumMemoryScanContext;

enum _GumMemoryValueType
{
  GUM_MEMORY_VALUE_POINTER,
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
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct _GumMemoryPatchContext
{
  GumDukHeapPtr apply;

  GumDukScope * scope;
};

struct _GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_error;
  GumDukHeapPtr on_complete;

  GumDukCore * core;
};

static GumDukMemory * gumjs_memory_module_from_args (const GumDukArgs * args);

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_check_code_pointer)

static int gum_duk_memory_read (GumMemoryValueType type,
    const GumDukArgs * args);
static int gum_duk_memory_write (GumMemoryValueType type,
    const GumDukArgs * args);

static void gum_duk_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumDukMemory * self);

#ifdef HAVE_WINDOWS
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUMJS_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
    { \
      return gum_duk_memory_read (GUM_MEMORY_VALUE_##T, args); \
    }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
    { \
      return gum_duk_memory_write (GUM_MEMORY_VALUE_##T, args); \
    }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
    GUMJS_DEFINE_MEMORY_READ (T); \
    GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    { "read" N, gumjs_memory_read_##T, 2 }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    { "write" N, gumjs_memory_write_##T, 2 }
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUMJS_EXPORT_MEMORY_READ (N, T), \
    GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUMJS_DEFINE_MEMORY_READ_WRITE (POINTER)
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
GUMJS_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_ansi_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf8_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf16_string)

GUMJS_DECLARE_FUNCTION (gumjs_memory_scan)
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static void gum_memory_scan_context_run (GumMemoryScanContext * self);
static gboolean gum_memory_scan_context_emit_match (GumAddress address,
    gsize size, GumMemoryScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumDukCore * core);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)
static void gum_duk_memory_clear_monitor (GumDukMemory * self,
    duk_context * ctx);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_memory_access_details_construct)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_operation)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_from)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_address)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_range_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_page_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_completed)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_total)

static const duk_function_list_entry gumjs_memory_functions[] =
{
  { "alloc", gumjs_memory_alloc, 1 },
  { "copy", gumjs_memory_copy, 3 },
  { "protect", gumjs_memory_protect, 3 },
  { "_patchCode", gumjs_memory_patch_code, 3 },
  { "_checkCodePointer", gumjs_memory_check_code_pointer, 1 },

  GUMJS_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER),
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
  GUMJS_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING),

  { "allocAnsiString", gumjs_memory_alloc_ansi_string, 1 },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string, 1 },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string, 1 },

  { "scan", gumjs_memory_scan, 4 },
  { "scanSync", gumjs_memory_scan_sync, 3 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_memory_access_monitor_functions[] =
{
  { "enable", gumjs_memory_access_monitor_enable, 2 },
  { "disable", gumjs_memory_access_monitor_disable, 0 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_memory_access_details_values[] =
{
  { "operation", gumjs_memory_access_details_get_operation, NULL },
  { "from", gumjs_memory_access_details_get_from, NULL },
  { "address", gumjs_memory_access_details_get_address, NULL },
  { "rangeIndex", gumjs_memory_access_details_get_range_index, NULL },
  { "pageIndex", gumjs_memory_access_details_get_page_index, NULL },
  { "pagesCompleted", gumjs_memory_access_details_get_pages_completed, NULL },
  { "pagesTotal", gumjs_memory_access_details_get_pages_total, NULL },

  { NULL, NULL, NULL }
};

void
_gum_duk_memory_init (GumDukMemory * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;
  self->monitor = NULL;
  self->on_access = NULL;

  _gum_duk_store_module_data (ctx, "memory", self);

  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_memory_functions);
  duk_put_global_string (ctx, "Memory");

  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_memory_access_monitor_functions);
  duk_put_global_string (ctx, "MemoryAccessMonitor");

  duk_push_c_function (ctx, gumjs_memory_access_details_construct, 0);
  duk_push_object (ctx);
  duk_put_prop_string (ctx, -2, "prototype");
  self->memory_access_details = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "MemoryAccessDetails");
  _gum_duk_add_properties_to_class (ctx, "MemoryAccessDetails",
      gumjs_memory_access_details_values);
}

void
_gum_duk_memory_dispose (GumDukMemory * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  gum_duk_memory_clear_monitor (self, ctx);

  _gum_duk_release_heapptr (ctx, self->memory_access_details);
}

void
_gum_duk_memory_finalize (GumDukMemory * self)
{
}

static GumDukMemory *
gumjs_memory_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "memory");
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  GumDukCore * core = args->core;
  gsize size, page_size;

  _gum_duk_args_parse (args, "Z", &size);

  if (size == 0 || size > 0x7fffffff)
    _gum_duk_throw (ctx, "invalid size");

  page_size = gum_query_page_size ();

  if ((size % page_size) != 0)
  {
    _gum_duk_push_native_resource (ctx, g_malloc0 (size), g_free, core);
  }
  else
  {
    _gum_duk_push_native_resource (ctx,
        gum_alloc_n_pages (size / page_size, GUM_PAGE_RW),
        gum_free_pages, core);
  }
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  GumDukCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer destination, source;
  gsize size;
  GumExceptorScope scope;

  _gum_duk_args_parse (args, "ppZ", &destination, &source, &size);

  if (size == 0)
    return 0;
  else if (size > 0x7fffffff)
    _gum_duk_throw (ctx, "invalid size");

  if (gum_exceptor_try (exceptor, &scope))
  {
    memmove (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_duk_throw_native (ctx, &scope.exception, core);
  }

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  gsize size;
  GumPageProtection prot;
  gboolean success;

  _gum_duk_args_parse (args, "pZm", &address, &size, &prot);

  if (size > 0x7fffffff)
    _gum_duk_throw (ctx, "invalid size");

  if (size != 0)
    success = gum_try_mprotect (address, size, prot);
  else
    success = TRUE;

  duk_push_boolean (ctx, success);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_patch_code)
{
  gpointer address;
  gsize size;
  GumMemoryPatchContext pc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);
  gboolean success;

  _gum_duk_args_parse (args, "pZF", &address, &size, &pc.apply);
  pc.scope = &scope;

  success = gum_memory_patch_code (address, size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success)
    _gum_duk_throw (ctx, "invalid address");

  return 0;
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  GumDukScope * scope = self->scope;
  duk_context * ctx = scope->ctx;

  duk_push_heapptr (ctx, self->apply);
  _gum_duk_push_native_pointer (ctx, mem, scope->core);
  _gum_duk_scope_call (scope, 1);
  duk_pop (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_check_code_pointer)
{
  const guint8 * ptr;
  GumDukCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  _gum_duk_args_parse (args, "p", &ptr);

  ptr = gum_strip_code_pointer ((gpointer) ptr);

#ifdef HAVE_ARM
  ptr = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~1);
#endif

  gum_ensure_code_readable (ptr, 1);

  if (gum_exceptor_try (exceptor, &scope))
  {
    duk_push_number (ctx, *ptr);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_duk_throw_native (ctx, &scope.exception, core);
  }

  return 1;
}

static int
gum_duk_memory_read (GumMemoryValueType type,
                     const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer address;
  gssize length = -1;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      _gum_duk_args_parse (args, "pZ", &address, &length);
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      _gum_duk_args_parse (args, "p|z", &address, &length);
      break;
    default:
      _gum_duk_args_parse (args, "p", &address);
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        _gum_duk_push_native_pointer (ctx, *((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        duk_push_number (ctx, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        duk_push_number (ctx, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        duk_push_number (ctx, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        duk_push_number (ctx, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        duk_push_number (ctx, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        duk_push_number (ctx, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        _gum_duk_push_int64 (ctx, *((gint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        _gum_duk_push_uint64 (ctx, *((guint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        _gum_duk_push_int64 (ctx, *((glong *) address), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        _gum_duk_push_uint64 (ctx, *((gulong *) address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        duk_push_number (ctx, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        duk_push_number (ctx, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        guint8 * data;

        data = address;
        if (data == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length > 0)
        {
          gpointer buffer_data;

          buffer_data = duk_push_fixed_buffer (ctx, length);
          memcpy (buffer_data, data, length);
        }
        else
        {
          duk_push_fixed_buffer (ctx, 0);
        }

        duk_push_buffer_object (ctx, -1, 0, MAX (length, 0),
            DUK_BUFOBJ_ARRAYBUFFER);

        duk_swap (ctx, -2, -1);
        duk_pop (ctx);

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * data;
        guint8 dummy_to_trap_bad_pointer_early;
        gchar * str;

        data = address;
        if (data == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        str = g_utf8_make_valid (data, length);
        duk_push_string (ctx, str);
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar * data;
        guint8 dummy_to_trap_bad_pointer_early;
        const gchar * end;

        data = address;
        if (data == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        if (!g_utf8_validate (data, length, &end))
        {
          _gum_duk_throw (ctx, "can't decode byte 0x%02x in position %u",
              (guint8) *end, (guint) (end - data));
        }

        if (length < 0)
        {
          duk_push_string (ctx, data);
        }
        else
        {
          gchar * slice;

          slice = g_strndup (data, length);
          duk_push_string (ctx, slice);
          g_free (slice);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gunichar2 * str_utf16;
        gchar * str_utf8;
        guint8 dummy_to_trap_bad_pointer_early;
        glong size;

        str_utf16 = address;
        if (str_utf16 == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, sizeof (guint8));

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        if (str_utf8 == NULL)
          _gum_duk_throw (ctx, "invalid string");
        duk_push_string (ctx, str_utf8);
        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        gchar * str_ansi;

        str_ansi = address;
        if (str_ansi == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          gchar * str_utf8;

          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          duk_push_string (ctx, str_utf8);
          g_free (str_utf8);
        }
        else
        {
          duk_push_string (ctx, "");
        }
#else
        _gum_duk_throw (ctx, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_duk_throw_native (ctx, &scope.exception, core);
  }

  return 1;
}

static int
gum_duk_memory_write (GumMemoryValueType type,
                      const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer address = NULL;
  gpointer pointer = NULL;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  GBytes * bytes = NULL;
  const gchar * str = NULL;
  gsize str_length = 0;
  gunichar2 * str_utf16 = NULL;
#ifdef HAVE_WINDOWS
  gchar * str_ansi = NULL;
#endif
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_POINTER:
      _gum_duk_args_parse (args, "pp", &address, &pointer);
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      _gum_duk_args_parse (args, "pz", &address, &s);
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      _gum_duk_args_parse (args, "pZ", &address, &u);
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      _gum_duk_args_parse (args, "pq", &address, &s64);
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      _gum_duk_args_parse (args, "pQ", &address, &u64);
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      _gum_duk_args_parse (args, "pn", &address, &number);
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      _gum_duk_args_parse (args, "pB", &address, &bytes);
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      _gum_duk_args_parse (args, "ps", &address, &str);

      str_length = g_utf8_strlen (str, -1);
      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);
#ifdef HAVE_WINDOWS
      else if (type == GUM_MEMORY_VALUE_ANSI_STRING)
        str_ansi = gum_ansi_string_from_utf8 (str);
#endif
      break;
    default:
      g_assert_not_reached ();
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        *((gpointer *) address) = pointer;
        break;
      case GUM_MEMORY_VALUE_S8:
        *((gint8 *) address) = (gint8) s;
        break;
      case GUM_MEMORY_VALUE_U8:
        *((guint8 *) address) = (guint8) u;
        break;
      case GUM_MEMORY_VALUE_S16:
        *((gint16 *) address) = (gint16) s;
        break;
      case GUM_MEMORY_VALUE_U16:
        *((guint16 *) address) = (guint16) u;
        break;
      case GUM_MEMORY_VALUE_S32:
        *((gint32 *) address) = (gint32) s;
        break;
      case GUM_MEMORY_VALUE_U32:
        *((guint32 *) address) = (guint32) u;
        break;
      case GUM_MEMORY_VALUE_S64:
        *((gint64 *) address) = s64;
        break;
      case GUM_MEMORY_VALUE_U64:
        *((guint64 *) address) = u64;
        break;
      case GUM_MEMORY_VALUE_LONG:
        *((glong *) address) = s64;
        break;
      case GUM_MEMORY_VALUE_ULONG:
        *((gulong *) address) = u64;
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        *((gfloat *) address) = number;
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        *((gdouble *) address) = number;
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        gconstpointer data;
        gsize size;

        data = g_bytes_get_data (bytes, &size);

        memcpy (address, data, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gsize size;

        size = g_utf8_offset_to_pointer (str, str_length) - str + 1;
        memcpy (address, str, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gsize size;

        size = (str_length + 1) * sizeof (gunichar2);
        memcpy (address, str_utf16, size);
        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        strcpy (address, str_ansi);
#else
        _gum_duk_throw (ctx, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_duk_throw_native (ctx, &scope.exception, core);
  }

  g_bytes_unref (bytes);
  g_free (str_utf16);
#ifdef HAVE_WINDOWS
  g_free (str_ansi);
#endif

  return 0;
}

#ifdef HAVE_WINDOWS

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  gint str_utf16_length;
  gsize str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      NULL, 0);
  str_utf16_size = (str_utf16_length + 1) * sizeof (WCHAR);
  str_utf16 = g_malloc (str_utf16_size);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      str_utf16, str_utf16_length);
  str_utf16[str_utf16_length] = L'\0';

  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);

  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  WCHAR * str_utf16;
  gchar * str_ansi;
  gint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  str_ansi_size = WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = g_malloc (str_ansi_size);

  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);

  g_free (str_utf16);

  return str_ansi;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef HAVE_WINDOWS
  const gchar * str;
  gchar * str_ansi;

  _gum_duk_args_parse (args, "s", &str);

  str_ansi = gum_ansi_string_from_utf8 (str);

  _gum_duk_push_native_resource (ctx, str_ansi, g_free, args->core);
  return 1;
#else
  _gum_duk_throw (ctx, "ANSI API is only applicable on Windows");
  return 0;
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  const gchar * str;

  _gum_duk_args_parse (args, "s", &str);

  _gum_duk_push_native_resource (ctx, g_strdup (str), g_free, args->core);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  const gchar * str;
  gunichar2 * str_utf16;

  _gum_duk_args_parse (args, "s", &str);

  str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

  _gum_duk_push_native_resource (ctx, str_utf16, g_free, args->core);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  GumDukCore * core = args->core;
  GumMemoryScanContext sc;
  gpointer address;
  gsize size;
  const gchar * match_str;

  _gum_duk_args_parse (args, "pZsF{onMatch,onError?,onComplete}",
      &address, &size, &match_str, &sc.on_match, &sc.on_error, &sc.on_complete);

  sc.range.base_address = GUM_ADDRESS (address);
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
      (GumScriptJobFunc) gum_memory_scan_context_run,
      g_slice_dup (GumMemoryScanContext, &sc),
      (GDestroyNotify) gum_memory_scan_context_free);

  return 0;
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
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

  g_slice_free (GumMemoryScanContext, self);
}

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  GumDukCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope exceptor_scope;
  GumDukScope script_scope;
  duk_context * ctx;

  if (gum_exceptor_try (exceptor, &exceptor_scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_memory_scan_context_emit_match, self);
  }

  ctx = _gum_duk_scope_enter (&script_scope, core);

  if (gum_exceptor_catch (exceptor, &exceptor_scope))
  {
    if (self->on_error != NULL)
    {
      gchar * message;

      duk_push_heapptr (ctx, self->on_error);

      message = gum_exception_details_to_string (&exceptor_scope.exception);
      duk_push_string (ctx, message);
      g_free (message);

      _gum_duk_scope_call (&script_scope, 1);
      duk_pop (ctx);
    }
  }

  duk_push_heapptr (ctx, self->on_complete);
  _gum_duk_scope_call (&script_scope, 0);
  duk_pop (ctx);

  _gum_duk_scope_leave (&script_scope);
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;
  gboolean proceed;

  ctx = _gum_duk_scope_enter (&scope, core);

  duk_push_heapptr (ctx, self->on_match);

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (address), core);
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

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  GumDukCore * core = args->core;
  gpointer address;
  gsize size;
  const gchar * match_str;
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumExceptorScope scope;

  _gum_duk_args_parse (args, "pZs", &address, &size, &match_str);

  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  pattern = gum_match_pattern_new_from_string (match_str);
  if (pattern == NULL)
    _gum_duk_throw (ctx, "invalid match pattern");

  duk_push_array (ctx);

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        core);
  }

  gum_match_pattern_free (pattern);

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gum_duk_throw_native (ctx, &scope.exception, core);
  }

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

  _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (address), core);
  duk_put_prop_string (ctx, -2, "address");

  duk_push_uint (ctx, size);
  duk_put_prop_string (ctx, -2, "size");

  duk_put_prop_index (ctx, -2, (duk_uarridx_t) duk_get_length (ctx, -2));

  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
  GumDukMemory * self;
  GArray * ranges;
  GumDukHeapPtr on_access;
  GError *error;

  self = gumjs_memory_module_from_args (args);

  _gum_duk_args_parse (args, "RF{onAccess}", &ranges, &on_access);

  if (ranges->len == 0)
  {
    g_array_free (ranges, TRUE);
    _gum_duk_throw (ctx, "expected one or more ranges");
  }

  gum_duk_memory_clear_monitor (self, ctx);

  _gum_duk_protect (ctx, on_access);
  self->on_access = on_access;
  self->monitor = gum_memory_access_monitor_new (
      (GumMemoryRange *) ranges->data, ranges->len, GUM_PAGE_RWX, TRUE,
      (GumMemoryAccessNotify) gum_duk_memory_on_access, self, NULL);

  g_array_free (ranges, TRUE);

  if (!gum_memory_access_monitor_enable (self->monitor, &error))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);

    gum_duk_memory_clear_monitor (self, ctx);

    (void) duk_throw (ctx);
  }

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
  GumDukMemory * self = gumjs_memory_module_from_args (args);

  gum_duk_memory_clear_monitor (self, ctx);

  return 0;
}

static void
gum_duk_memory_clear_monitor (GumDukMemory * self,
                              duk_context * ctx)
{
  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  if (self->on_access != NULL)
  {
    _gum_duk_unprotect (ctx, self->on_access);
    self->on_access = NULL;
  }
}

static void
gum_duk_memory_on_access (GumMemoryAccessMonitor * monitor,
                          const GumMemoryAccessDetails * details,
                          GumDukMemory * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);

  duk_push_heapptr (ctx, self->memory_access_details);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, (gpointer) details);

  duk_push_heapptr (ctx, self->on_access);
  duk_dup (ctx, -2);
  _gum_duk_scope_call (&scope, 1);

  _gum_duk_put_data (ctx, -2, NULL);

  _gum_duk_scope_leave (&scope);
}

static const GumMemoryAccessDetails *
gumjs_memory_access_details_from_args (const GumDukArgs * args)
{
  const GumMemoryAccessDetails * details;
  duk_context * ctx = args->ctx;

  duk_push_this (ctx);
  details = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  if (details == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  return details;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_memory_access_details_construct)
{
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_operation)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  duk_push_string (ctx,
      _gum_duk_memory_operation_to_string (details->operation));

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_from)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  _gum_duk_push_native_pointer (ctx, details->from, args->core);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_address)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  _gum_duk_push_native_pointer (ctx, details->address, args->core);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_range_index)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  duk_push_number (ctx, details->range_index);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_page_index)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  duk_push_number (ctx, details->page_index);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_pages_completed)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  duk_push_number (ctx, details->pages_completed);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_pages_total)
{
  const GumMemoryAccessDetails * details =
      gumjs_memory_access_details_from_args (args);

  duk_push_number (ctx, details->pages_total);

  return 1;
}
