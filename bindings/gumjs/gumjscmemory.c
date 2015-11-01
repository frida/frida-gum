/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscmemory.h"

#include "gumjscmacros.h"

typedef guint GumMemoryValueType;
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
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct _GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  JSObjectRef on_match;
  JSObjectRef on_error;
  JSObjectRef on_complete;

  GumJscCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)

static JSValueRef gum_jsc_memory_read (GumJscMemory * self,
    GumMemoryValueType type, const GumJscArgs * args,
    JSValueRef * exception);
static JSValueRef gum_jsc_memory_write (GumJscMemory * self,
    GumMemoryValueType type, const GumJscArgs * args,
    JSValueRef * exception);

#ifdef G_OS_WIN32
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUMJS_DEFINE_MEMORY_READ(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
  { \
    return gum_jsc_memory_read (JSObjectGetPrivate (this_object), \
        GUM_MEMORY_VALUE_##T, args, exception); \
  }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
  { \
    return gum_jsc_memory_write (JSObjectGetPrivate (this_object), \
        GUM_MEMORY_VALUE_##T, args, exception); \
  }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
  GUMJS_DEFINE_MEMORY_READ (T); \
  GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
  { "read" N, gumjs_memory_read_##T, GUMJS_RO }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
  { "write" N, gumjs_memory_write_##T, GUMJS_RO }
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
    gsize size, gpointer user_data);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)

static const JSStaticFunction gumjs_memory_functions[] =
{
  { "alloc", gumjs_memory_alloc, GUMJS_RO },
  { "copy", gumjs_memory_copy, GUMJS_RO },
  { "protect", gumjs_memory_protect, GUMJS_RO },

  GUMJS_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUMJS_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING),

  { "allocAnsiString", gumjs_memory_alloc_ansi_string, GUMJS_RO },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string, GUMJS_RO },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string, GUMJS_RO },

  { "scan", gumjs_memory_scan, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_memory_access_monitor_functions[] =
{
  { "enable", gumjs_memory_access_monitor_enable, GUMJS_RO },
  { "disable", gumjs_memory_access_monitor_disable, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_jsc_memory_init (GumJscMemory * self,
                      GumJscCore * core,
                      JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef memory, memory_access_monitor;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Memory";
  def.staticFunctions = gumjs_memory_functions;
  klass = JSClassCreate (&def);
  memory = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, memory);

  def = kJSClassDefinitionEmpty;
  def.className = "MemoryAccessMonitor";
  def.staticFunctions = gumjs_memory_access_monitor_functions;
  klass = JSClassCreate (&def);
  memory_access_monitor = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, memory_access_monitor);
}

void
_gum_jsc_memory_dispose (GumJscMemory * self)
{
  (void) self;
}

void
_gum_jsc_memory_finalize (GumJscMemory * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  GumJscCore * core = args->core;
  guint size, page_size;
  JSObjectRef handle;

  if (!_gumjs_args_parse (args, "u", &size))
    return NULL;
  if (size == 0 || size > 0x7fffffff)
    goto invalid_size;

  page_size = gum_query_page_size ();

  if (size < page_size)
  {
    _gumjs_native_resource_new (ctx, g_malloc (size), g_free, core, &handle);
  }
  else
  {
    guint n = ((size + page_size - 1) & ~(page_size - 1)) / page_size;
    _gumjs_native_resource_new (ctx,
        gum_alloc_n_pages (n, GUM_PAGE_RW), gum_free_pages, core, &handle);
  }

  return handle;

invalid_size:
  {
    _gumjs_throw (ctx, exception, "invalid size");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  GumJscCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer destination, source;
  guint size;
  GumExceptorScope scope;

  if (!_gumjs_args_parse (args, "ppu", &destination, &source, &size))
    return NULL;
  if (size == 0)
    goto beach;
  else if (size > 0x7fffffff)
    goto invalid_size;

  if (gum_exceptor_try (exceptor, &scope))
  {
    memcpy (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (ctx, exception, &scope.exception, core);
  }

beach:
  return JSValueMakeUndefined (ctx);

invalid_size:
  {
    _gumjs_throw (ctx, exception, "invalid size");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  guint size;
  GumPageProtection prot;
  gboolean success = TRUE;

  if (!_gumjs_args_parse (args, "pum", &address, &size, &prot))
    return NULL;
  if (size == 0)
    goto beach;
  else if (size > 0x7fffffff)
    goto invalid_size;

  success = gum_try_mprotect (address, size, prot);

beach:
  return JSValueMakeBoolean (ctx, success ? true : false);

invalid_size:
  {
    _gumjs_throw (ctx, exception, "invalid size");
    return NULL;
  }
}

static JSValueRef
gum_jsc_memory_read (GumJscMemory * self,
                     GumMemoryValueType type,
                     const GumJscArgs * args,
                     JSValueRef * exception)
{
  JSContextRef ctx = args->ctx;
  GumJscCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  JSValueRef result = NULL;
  gpointer address;
  gint length = -1;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gumjs_args_parse (args, "pi", &address, &length))
        return NULL;
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gumjs_args_parse (args, "p|i", &address, &length))
        return NULL;
      break;
    default:
      if (!_gumjs_args_parse (args, "p", &address))
        return NULL;
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gumjs_native_pointer_new (ctx, *((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = JSValueMakeNumber (ctx, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = JSValueMakeNumber (ctx, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = JSValueMakeNumber (ctx, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = JSValueMakeNumber (ctx, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = JSValueMakeNumber (ctx, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = JSValueMakeNumber (ctx, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = JSValueMakeNumber (ctx, *((gint64 *) address));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = JSValueMakeNumber (ctx, *((guint64 *) address));
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = JSValueMakeNumber (ctx, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = JSValueMakeNumber (ctx, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        guint8 * data;

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        if (length > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          JSObjectRef array;
          gpointer array_data;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          array = _gumjs_array_buffer_new (ctx, length, core);
          array_data = _gumjs_array_buffer_get_data (ctx, array, NULL);
          memcpy (array_data, data, length);
          result = array;
        }
        else
        {
          result = _gumjs_array_buffer_new (ctx, 0, core);
        }

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * data;
        guint8 dummy_to_trap_bad_pointer_early;

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

        if (length < 0)
        {
          result = _gumjs_string_to_value (ctx, data);
        }
        else
        {
          gchar * slice;

          slice = g_strndup (data, length);
          result = _gumjs_string_to_value (ctx, slice);
          g_free (slice);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar * data;
        guint8 dummy_to_trap_bad_pointer_early;

        data = address;
        if (data == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

        if (length < 0)
        {
          result = _gumjs_string_to_value (ctx, data);
        }
        else
        {
          gsize size;
          gchar * slice;

          size = g_utf8_offset_to_pointer (data, length) - data;
          slice = g_strndup (data, size);
          result = _gumjs_string_to_value (ctx, slice);
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
          result = JSValueMakeNull (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        result = _gumjs_string_to_value (ctx, str_utf8);
        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef G_OS_WIN32
        gchar * str_ansi;

        str_ansi = address;
        if (str_ansi == NULL)
        {
          result = JSValueMakeNull (ctx);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          gchar * str_utf8;

          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          result = _gumjs_string_to_value (ctx, str_utf8);
          g_free (str_utf8);
        }
        else
        {
          result = _gumjs_string_to_value (ctx, "");
        }
#else
        _gumjs_throw (ctx, exception, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (ctx, exception, &scope.exception, core);
  }

  return result;
}

static JSValueRef
gum_jsc_memory_write (GumJscMemory * self,
                      GumMemoryValueType type,
                      const GumJscArgs * args,
                      JSValueRef * exception)
{
  JSContextRef ctx = args->ctx;
  GumJscCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer address;
  gpointer pointer;
  gdouble number;
  GBytes * bytes = NULL;
  gchar * str = NULL;
  gsize str_length;
  gunichar2 * str_utf16 = NULL;
#ifdef G_OS_WIN32
  gchar * str_ansi = NULL;
#endif
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_POINTER:
      if (!_gumjs_args_parse (args, "pp", &address, &pointer))
        return NULL;
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_S32:
    case GUM_MEMORY_VALUE_U32:
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gumjs_args_parse (args, "pn", &address, &number))
        return NULL;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gumjs_args_parse (args, "pB", &address, &bytes))
        return NULL;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gumjs_args_parse (args, "ps", &address, &str))
        return NULL;
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
        *((gint8 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_U8:
        *((guint8 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_S16:
        *((gint16 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_U16:
        *((guint16 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_S32:
        *((gint32 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_U32:
        *((guint32 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_S64:
        *((gint64 *) address) = number;
        break;
      case GUM_MEMORY_VALUE_U64:
        *((guint64 *) address) = number;
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
#ifdef G_OS_WIN32
        strcpy (address, str_ansi);
#else
        _gumjs_throw (ctx, exception, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (ctx, exception, &scope.exception, core);
  }

  g_bytes_unref (bytes);
  g_free (str);
  g_free (str_utf16);
#ifdef G_OS_WIN32
  g_free (str_ansi);
#endif

  return JSValueMakeUndefined (ctx);
}

#ifdef G_OS_WIN32

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  guint str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_size = (guint) (length + 1) * sizeof (WCHAR);
  str_utf16 = (WCHAR *) g_malloc (str_utf16_size);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, length, str_utf16, str_utf16_size);
  str_utf16[length] = L'\0';
  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);
  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  gunichar2 * str_utf16;
  gchar * str_ansi;
  guint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  str_ansi_size = WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = (gchar *) g_malloc (str_ansi_size);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);
  g_free (str_utf16);

  return str_ansi;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef G_OS_WIN32
  gchar * str, * str_ansi;
  JSObjectRef handle;

  if (!_gumjs_args_parse (args, "s", &str))
    return NULL;
  str_ansi = gum_ansi_string_from_utf8 (str);
  g_free (str);

  _gumjs_native_resource_new (ctx, str_ansi, g_free, args->core, &handle);

  return handle;
#else
  _gumjs_throw (ctx, exception, "ANSI API is only applicable on Windows");
  return NULL;
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  gchar * str;
  JSObjectRef handle;

  if (!_gumjs_args_parse (args, "s", &str))
    return NULL;

  _gumjs_native_resource_new (ctx, str, g_free, args->core, &handle);

  return handle;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  gchar * str;
  gunichar2 * str_utf16;
  JSObjectRef handle;

  if (!_gumjs_args_parse (args, "s", &str))
    return NULL;
  str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);
  g_free (str);

  _gumjs_native_resource_new (ctx, str_utf16, g_free, args->core, &handle);

  return handle;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  GumJscCore * core = args->core;
  GumMemoryScanContext sc;
  gpointer address;
  guint size;
  gchar * match_str;

  if (!_gumjs_args_parse (args, "pusF{onMatch,onError?,onComplete}", &address,
      &size, &match_str, &sc.on_match, &sc.on_error, &sc.on_complete))
    return NULL;
  sc.range.base_address = GUM_ADDRESS (address);
  sc.range.size = size;
  sc.pattern = gum_match_pattern_new_from_string (match_str);
  sc.core = core;
  g_free (match_str);

  if (sc.pattern == NULL)
    goto invalid_match_pattern;

  JSValueProtect (ctx, sc.on_match);
  if (sc.on_error != NULL)
    JSValueProtect (ctx, sc.on_error);
  JSValueProtect (ctx, sc.on_complete);

  _gum_jsc_core_push_job (core,
      (GumScriptJobFunc) gum_memory_scan_context_run,
      g_slice_dup (GumMemoryScanContext, &sc),
      (GDestroyNotify) gum_memory_scan_context_free);

  return JSValueMakeUndefined (ctx);

invalid_match_pattern:
  {
    _gumjs_throw (ctx, exception, "invalid match pattern");
    return NULL;
  }
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * ctx)
{
  JSContextRef js_ctx = ctx->core->ctx;

  gum_match_pattern_free (ctx->pattern);

  JSValueUnprotect (js_ctx, ctx->on_match);
  if (ctx->on_error != NULL)
    JSValueUnprotect (js_ctx, ctx->on_error);
  JSValueUnprotect (js_ctx, ctx->on_complete);

  g_slice_free (GumMemoryScanContext, ctx);
}

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  GumJscCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope exceptor_scope;
  GumJscScope script_scope;
  JSContextRef ctx = core->ctx;

  if (gum_exceptor_try (exceptor, &exceptor_scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        gum_memory_scan_context_emit_match, self);
  }

  _gum_jsc_scope_enter (&script_scope, core);

  if (gum_exceptor_catch (exceptor, &exceptor_scope))
  {
    if (self->on_error != NULL)
    {
      gchar * message;
      JSValueRef message_value;

      message = gum_exception_details_to_string (&exceptor_scope.exception);
      message_value = _gumjs_string_to_value (ctx, message);
      g_free (message);

      JSObjectCallAsFunction (ctx, self->on_error, NULL, 1, &message_value,
          &script_scope.exception);

      _gum_jsc_scope_flush (&script_scope);
    }
  }

  JSObjectCallAsFunction (ctx, self->on_complete, NULL, 0, NULL,
      &script_scope.exception);

  _gum_jsc_scope_leave (&script_scope);
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    gpointer user_data)
{
  GumMemoryScanContext * self = user_data;
  GumJscCore * core = self->core;
  GumJscScope scope;
  JSContextRef ctx = self->core->ctx;
  JSValueRef args[2], result;
  gboolean proceed;
  gchar * str;

  _gum_jsc_scope_enter (&scope, core);

  args[0] = _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
  args[1] = JSValueMakeNumber (ctx, size);

  result = JSObjectCallAsFunction (ctx, self->on_match, NULL,
      G_N_ELEMENTS (args), args, &scope.exception);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  _gum_jsc_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
#ifdef G_OS_WIN32
# error Please add MemoryAccessMonitor to the JavaScriptCore runtime
#else
  _gumjs_throw (ctx, exception,
      "MemoryAccessMonitor is only available on Windows for now");
  return NULL;
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
#ifdef G_OS_WIN32
# error Please add MemoryAccessMonitor to the JavaScriptCore runtime
#else
  _gumjs_throw (ctx, exception,
      "MemoryAccessMonitor is only available on Windows for now");
  return NULL;
#endif
}
