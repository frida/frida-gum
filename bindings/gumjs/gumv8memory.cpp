/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8memory.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <string.h>
#include <wchar.h>
#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

#define GUMJS_MODULE_NAME Memory

using namespace v8;

enum GumMemoryValueType
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

struct GumMemoryPatchContext
{
  Local<Function> apply;
  gboolean has_pending_exception;

  GumV8Core * core;
};

struct GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumPersistent<Function>::type * on_match;
  GumPersistent<Function>::type * on_error;
  GumPersistent<Function>::type * on_complete;

  GumV8Core * core;
};

struct GumMemoryScanSyncContext
{
  Local<Array> matches;

  GumV8Core * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);

static void gum_v8_memory_read (GumMemoryValueType type,
    const GumV8Args * args, ReturnValue<Value> return_value);
static void gum_v8_memory_write (GumMemoryValueType type,
    const GumV8Args * args);

#ifdef G_OS_WIN32
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUM_DEFINE_MEMORY_READ(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
  { \
    gum_v8_memory_read (GUM_MEMORY_VALUE_##T, args, info.GetReturnValue ()); \
  }
#define GUM_DEFINE_MEMORY_WRITE(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
  { \
    gum_v8_memory_write (GUM_MEMORY_VALUE_##T, args); \
  }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
  GUM_DEFINE_MEMORY_READ (T); \
  GUM_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
  { "read" N, gumjs_memory_read_##T }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
  { "write" N, gumjs_memory_write_##T }
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
  GUMJS_EXPORT_MEMORY_READ (N, T), \
  GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUM_DEFINE_MEMORY_READ_WRITE (POINTER)
GUM_DEFINE_MEMORY_READ_WRITE (S8)
GUM_DEFINE_MEMORY_READ_WRITE (U8)
GUM_DEFINE_MEMORY_READ_WRITE (S16)
GUM_DEFINE_MEMORY_READ_WRITE (U16)
GUM_DEFINE_MEMORY_READ_WRITE (S32)
GUM_DEFINE_MEMORY_READ_WRITE (U32)
GUM_DEFINE_MEMORY_READ_WRITE (S64)
GUM_DEFINE_MEMORY_READ_WRITE (U64)
GUM_DEFINE_MEMORY_READ_WRITE (LONG)
GUM_DEFINE_MEMORY_READ_WRITE (ULONG)
GUM_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUM_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ (C_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_ansi_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf8_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf16_string)

GUMJS_DECLARE_FUNCTION (gumjs_memory_scan)
static void gum_memory_scan_context_free (GumMemoryScanContext * self);
static void gum_memory_scan_context_run (GumMemoryScanContext * self);
static gboolean gum_memory_scan_context_emit_match (GumAddress address,
    gsize size, GumMemoryScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumMemoryScanSyncContext * ctx);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)
static void gum_v8_memory_clear_monitor (GumV8Memory * self);
#ifdef G_OS_WIN32
static void gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumV8Memory * self);
#endif

static const GumV8Function gumjs_memory_functions[] =
{
  { "alloc", gumjs_memory_alloc },
  { "copy", gumjs_memory_copy },
  { "protect", gumjs_memory_protect },
  { "_patchCode", gumjs_memory_patch_code },

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

  { "allocAnsiString", gumjs_memory_alloc_ansi_string },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string },

  { "scan", gumjs_memory_scan },
  { "scanSync", gumjs_memory_scan_sync },

  { NULL, NULL }
};

static const GumV8Function gumjs_memory_access_monitor_functions[] =
{
  { "enable", gumjs_memory_access_monitor_enable },
  { "disable", gumjs_memory_access_monitor_disable },

  { NULL, NULL }
};

void
_gum_v8_memory_init (GumV8Memory * self,
                         GumV8Core * core,
                         Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto memory = _gum_v8_create_module ("Memory", scope, isolate);
  _gum_v8_module_add (module, memory, gumjs_memory_functions, isolate);

  auto monitor = _gum_v8_create_module ("MemoryAccessMonitor", scope, isolate);
  _gum_v8_module_add (module, monitor, gumjs_memory_access_monitor_functions,
      isolate);
}

void
_gum_v8_memory_realize (GumV8Memory * self)
{
  (void) self;
}

void
_gum_v8_memory_dispose (GumV8Memory * self)
{
  gum_v8_memory_clear_monitor (self);
}

void
_gum_v8_memory_finalize (GumV8Memory * self)
{
  g_clear_object (&self->monitor);
}

/*
 * Prototype:
 * Memory.alloc(size)
 *
 * Docs:
 * Allocate a zero-initialized chunk of memory
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  gsize size;
  if (!_gum_v8_args_parse (args, "Z", &size))
    return;

  if (size == 0 || size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  GumV8NativeResource * res;

  gsize page_size = gum_query_page_size ();
  if (size < page_size)
  {
    res = _gum_v8_native_resource_new (g_malloc0 (size), size, g_free, core);
  }
  else
  {
    guint n = ((size + page_size - 1) & ~(page_size - 1)) / page_size;
    res = _gum_v8_native_resource_new (gum_alloc_n_pages (n, GUM_PAGE_RW),
        n * page_size, gum_free_pages, core);
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

/*
 * Prototype:
 * Memory.copy(destination, source, size)
 *
 * Docs:
 * Copies a specified number of bytes from one memory location to another
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  gpointer destination, source;
  gsize size;
  if (!_gum_v8_args_parse (args, "ppZ", &destination, &source, &size))
    return;

  if (size == 0)
  {
    return;
  }
  else if (size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  auto exceptor = args->core->exceptor;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    memcpy (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
}

/*
 * Prototype:
 * Memory.protect(address, size, prot)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
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
    success = !!gum_try_mprotect (address, size, prot);
  else
    success = true;

  info.GetReturnValue ().Set (success);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_patch_code)
{
  gpointer address;
  gsize size;
  GumMemoryPatchContext pc;
  gboolean success;

  if (!_gum_v8_args_parse (args, "pZF", &address, &size, &pc.apply))
    return;
  pc.has_pending_exception = FALSE;
  pc.core = core;

  success = gum_memory_patch_code (GUM_ADDRESS (address), size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success && !pc.has_pending_exception)
    _gum_v8_throw_ascii_literal (isolate, "invalid address");
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  Handle<Value> argv[] = {
    _gum_v8_native_pointer_new (mem, self->core)
  };
  auto result = self->apply->Call (Undefined (self->core->isolate),
      G_N_ELEMENTS (argv), argv);
  self->has_pending_exception = result.IsEmpty ();
}

static void
gum_v8_memory_read (GumMemoryValueType type,
                    const GumV8Args * args,
                    ReturnValue<Value> return_value)
{
  auto core = args->core;
  auto isolate = core->isolate;
  auto exceptor = core->exceptor;
  gpointer address;
  gssize length = -1;
  GumExceptorScope scope;
  Local<Value> result;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_v8_args_parse (args, "pZ", &address, &length))
        return;
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_v8_args_parse (args, "p|z", &address, &length))
        return;
      break;
    default:
      if (!_gum_v8_args_parse (args, "p", &address))
        return;
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_v8_native_pointer_new (*((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (isolate, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (isolate, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (isolate, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (isolate, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (isolate, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (isolate, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_v8_int64_new (*((gint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_v8_uint64_new (*((guint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_v8_int64_new (*((glong *) address), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_v8_uint64_new (*((gulong *) address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = Number::New (isolate, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = Number::New (isolate, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        auto data = (guint8 *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

          result = ArrayBuffer::New (isolate, g_memdup (data, length), length,
              ArrayBufferCreationMode::kInternalized);
        }
        else
        {
          result = ArrayBuffer::New (isolate, 0);
        }

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        auto data = (gchar *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

          result = String::NewFromOneByte (isolate, (const uint8_t *) data,
              NewStringType::kNormal, length).ToLocalChecked ();
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        auto data = (gchar *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

          result = String::NewFromUtf8 (isolate, data, String::kNormalString,
              length);
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        auto str_utf16 = (gunichar2 *) address;
        if (str_utf16 == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, sizeof (guint8));
        }

        glong size;
        auto str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        if (str_utf8 == NULL)
        {
          _gum_v8_throw_ascii_literal (isolate, "invalid string");
          break;
        }

        if (size != 0)
        {
          result = String::NewFromUtf8 (isolate, str_utf8,
              String::kNormalString, size);
        }
        else
        {
          result = String::Empty (isolate);
        }

        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef G_OS_WIN32
        auto str_ansi = (gchar *) address;
        if (str_ansi == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          auto str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          auto size = g_utf8_offset_to_pointer (str_utf8,
              g_utf8_strlen (str_utf8, -1)) - str_utf8;
          result = String::NewFromUtf8 (isolate, str_utf8,
              String::kNormalString, size);
          g_free (str_utf8);
        }
        else
        {
          result = String::Empty (isolate);
        }
#else
        _gum_v8_throw_ascii_literal (isolate,
            "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
  else
  {
    if (!result.IsEmpty ())
      return_value.Set (result);
  }
}

static void
gum_v8_memory_write (GumMemoryValueType type,
                     const GumV8Args * args)
{
  gpointer address = NULL;
  gpointer pointer = NULL;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  GBytes * bytes = NULL;
  gchar * str = NULL;
  gsize str_length = 0;
  gunichar2 * str_utf16 = NULL;
#ifdef G_OS_WIN32
  gchar * str_ansi = NULL;
#endif
  auto core = args->core;
  auto exceptor = core->exceptor;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_POINTER:
      if (!_gum_v8_args_parse (args, "pp", &address, &pointer))
        return;
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_v8_args_parse (args, "pz", &address, &s))
        return;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_v8_args_parse (args, "pZ", &address, &u))
        return;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_v8_args_parse (args, "pq", &address, &s64))
        return;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_v8_args_parse (args, "pQ", &address, &u64))
        return;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_v8_args_parse (args, "pn", &address, &number))
        return;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_v8_args_parse (args, "pB", &address, &bytes))
        return;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_v8_args_parse (args, "ps", &address, &str))
        return;

      str_length = g_utf8_strlen (str, -1);
      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);
#ifdef G_OS_WIN32
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
        gsize size;
        auto data = g_bytes_get_data (bytes, &size);
        memcpy (address, data, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gsize size = g_utf8_offset_to_pointer (str, str_length) - str + 1;
        memcpy (address, str, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gsize size = (str_length + 1) * sizeof (gunichar2);
        memcpy (address, str_utf16, size);
        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef G_OS_WIN32
        strcpy ((char *) address, str_ansi);
#else
        _gum_v8_throw_ascii_literal (core->isolate,
            "ANSI API is only applicable on Windows");
#endif
        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }

  g_bytes_unref (bytes);
  g_free (str);
  g_free (str_utf16);
#ifdef G_OS_WIN32
  g_free (str_ansi);
#endif
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

#ifdef G_OS_WIN32

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  if (length < 0)
    length = (gint) strlen (str_ansi);

  auto str_utf16_size = (guint) ((length + 1) * sizeof (WCHAR));
  auto str_utf16 = (WCHAR *) g_malloc (str_utf16_size);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, length, str_utf16, str_utf16_size);
  str_utf16[length] = L'\0';
  auto str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL,
      NULL);
  g_free (str_utf16);
  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  auto str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  guint str_ansi_size = WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      NULL, 0, NULL, NULL);
  auto str_ansi = (gchar *) g_malloc (str_ansi_size);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1, str_ansi,
      str_ansi_size, NULL, NULL);
  g_free (str_utf16);
  return str_ansi;
}

#endif

/*
 * Prototype:
 * Memory.allocAnsiString(string)
 *
 * Docs:
 * Windows only. Allocates an ANSI string and returns a pointer.
 *
 * Example:
 * -> Memory.allocAnsiString("Frida Rocks!")
 * "0x1110c7da0"
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef G_OS_WIN32
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;
  auto str_ansi = gum_ansi_string_from_utf8 (str);
  g_free (str);

  auto res = _gum_v8_native_resource_new (str_ansi, strlen (str_ansi), g_free,
      core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
#else
  _gum_v8_throw_ascii_literal (isolate,
      "ANSI API is only applicable on Windows");
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;

  auto res = _gum_v8_native_resource_new (str, strlen (str), g_free, core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

/*
 * Prototype:
 * Memory.allocUtf16String(string)
 *
 * Docs:
 * Allocates a UTF-16 string and returns a pointer.
 *
 * Example:
 * -> Memory.allocUtf16String("Frida Rocks!")
 * "0x11139d6f0"
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;
  glong items_written;
  auto str_utf16 = g_utf8_to_utf16 (str, -1, NULL, &items_written, NULL);
  g_free (str);

  gsize size = (items_written + 1) * sizeof (gunichar2);

  GumV8NativeResource * res = _gum_v8_native_resource_new (str_utf16, size,
      g_free, core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

/*
 * Prototype:
 * Memory.scan(address, size, match_str, callback)
 *
 * Docs:
 * Scans a memory region for a specific string
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  gpointer address;
  gsize size;
  gchar * match_str;
  Local<Function> on_match, on_error, on_complete;
  if (!_gum_v8_args_parse (args, "pZsF{onMatch,onError?,onComplete}",
      &address, &size, &match_str, &on_match, &on_error, &on_complete))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  auto pattern = gum_match_pattern_new_from_string (match_str);

  g_free (match_str);

  if (pattern != NULL)
  {
    auto ctx = g_slice_new0 (GumMemoryScanContext);
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = new GumPersistent<Function>::type (isolate, on_match);
    if (!on_error.IsEmpty ())
      ctx->on_error = new GumPersistent<Function>::type (isolate, on_error);
    ctx->on_complete = new GumPersistent<Function>::type (isolate, on_complete);
    ctx->core = core;

    _gum_v8_core_pin (core);
    _gum_v8_core_push_job (core, (GumScriptJobFunc) gum_memory_scan_context_run,
        ctx, (GDestroyNotify) gum_memory_scan_context_free);
  }
  else
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid match pattern");
  }
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
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

  g_slice_free (GumMemoryScanContext, self);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  auto core = self->core;
  auto exceptor = core->exceptor;
  auto isolate = core->isolate;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_memory_scan_context_emit_match, self);
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
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;

  auto on_match = Local<Function>::New (isolate, *self->on_match);
  Handle<Value> argv[] = {
    _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), self->core),
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
 * Memory.scanSync(address, size, match_str)
 *
 * Docs:
 * Scans a memory region for a specific string
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  gpointer address;
  gsize size;
  gchar * match_str;
  if (!_gum_v8_args_parse (args, "pZs", &address, &size, &match_str))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  auto pattern = gum_match_pattern_new_from_string (match_str);

  g_free (match_str);

  if (pattern == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid match pattern");
    return;
  }

  GumMemoryScanSyncContext ctx;
  ctx.matches = Array::New (isolate);
  ctx.core = core;

  GumExceptorScope scope;

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
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
                  GumMemoryScanSyncContext * ctx)
{
  GumV8Core * core = ctx->core;

  auto match = Object::New (core->isolate);
  _gum_v8_object_set_pointer (match, "address", address, core);
  _gum_v8_object_set_uint (match, "size", size, core);
  ctx->matches->Set (core->isolate->GetCurrentContext (),
      ctx->matches->Length (), match).ToChecked ();

  return TRUE;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

/*
 * Prototype:
 * MemoryAccessMonitor.enable(num_ranges, callback)
 *
 * Docs:
 * Windows only. TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
#ifdef G_OS_WIN32
  GArray * ranges;
  Local<Function> on_access;
  if (!_gum_v8_args_parse (args, "RF{onAccess}", &ranges, &on_access))
    return;

  if (ranges->len == 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "expected one or more ranges");
    g_array_free (ranges, TRUE);
    return;
  }

  if (module->monitor != NULL)
  {
    gum_memory_access_monitor_disable (module->monitor);
    g_object_unref (module->monitor);
    module->monitor = NULL;
  }

  module->monitor = gum_memory_access_monitor_new (
      (GumMemoryRange *) ranges->data, ranges->len, GUM_PAGE_RWX, TRUE,
      (GumMemoryAccessNotify) gum_v8_memory_on_access, module, NULL);

  g_array_free (ranges, TRUE);

  delete module->on_access;
  module->on_access = new GumPersistent<Function>::type (isolate, on_access);

  GError * error = NULL;
  if (!gum_memory_access_monitor_enable (module->monitor, &error))
  {
    _gum_v8_throw_literal (isolate, error->message);
    g_error_free (error);

    delete module->on_access;
    module->on_access = nullptr;

    g_object_unref (module->monitor);
    module->monitor = NULL;
  }
#else
  _gum_v8_throw_ascii_literal (isolate,
      "MemoryAccessMonitor is only available on Windows for now");
#endif
}

/*
 * Prototype:
 * MemoryAccessMonitor.disable()
 *
 * Docs:
 * Windows only. TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
#ifdef G_OS_WIN32
  gum_v8_memory_clear_monitor (module);
#else
  _gum_v8_throw_ascii_literal (isolate,
      "MemoryAccessMonitor is only available on Windows for now");
#endif
}

static void
gum_v8_memory_clear_monitor (GumV8Memory * self)
{
#ifdef G_OS_WIN32
  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  delete self->on_access;
  self->on_access = nullptr;
#else
  (void) self;
#endif
}

#ifdef G_OS_WIN32

static void
gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
                         const GumMemoryAccessDetails * details,
                         GumV8Memory * self)
{
  auto core = self->core;
  auto isolate = core->isolate;
  ScriptScope script_scope (core->script);

  (void) monitor;

  auto d = Object::New (isolate);
  _gum_v8_object_set_ascii (d, "operation",
      _gum_v8_memory_operation_to_string (details->operation), core);
  _gum_v8_object_set_pointer (d, "from", details->from, core);
  _gum_v8_object_set_pointer (d, "address", details->address, core);

  _gum_v8_object_set_uint (d, "rangeIndex", details->range_index, core);
  _gum_v8_object_set_uint (d, "pageIndex", details->page_index, core);
  _gum_v8_object_set_uint (d, "pagesCompleted", details->pages_completed, core);
  _gum_v8_object_set_uint (d, "pagesTotal", details->pages_total, core);

  auto on_access (Local<Function>::New (isolate, *self->on_access));
  Handle<Value> argv[] = { d };
  auto result = on_access->Call (isolate->GetCurrentContext (),
      Undefined (isolate), G_N_ELEMENTS (argv), argv);
  (void) result;
}

#endif
