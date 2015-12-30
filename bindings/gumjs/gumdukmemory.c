/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukmemory.h"

#include "gumdukmacros.h"

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
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_error;
  GumDukHeapPtr on_complete;

  GumDukCore * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_memory_construct)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)

static int gum_duk_memory_read (GumDukMemory * self,
    GumMemoryValueType type, const GumDukArgs * args);
static int gum_duk_memory_write (GumDukMemory * self,
    GumMemoryValueType type, const GumDukArgs * args);

#ifdef G_OS_WIN32
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUMJS_DEFINE_MEMORY_READ(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
  { \
    return gum_duk_memory_read (_gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx)), \
        GUM_MEMORY_VALUE_##T, args); \
  }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
  GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
  { \
    return gum_duk_memory_write (_gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx)), \
        GUM_MEMORY_VALUE_##T, args); \
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

static const duk_function_list_entry gumjs_memory_functions[] =
{
  { "alloc", gumjs_memory_alloc, 1 },
  { "copy", gumjs_memory_copy, 3 },
  { "protect", gumjs_memory_protect, 3 },

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

  { "allocAnsiString", gumjs_memory_alloc_ansi_string, 1 },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string, 1 },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string, 1 },

  { "scan", gumjs_memory_scan, 4 },

  { NULL, NULL, 0 }
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_memory_access_monitor_construct)
static const duk_function_list_entry gumjs_memory_access_monitor_functions[] =
{
  { "enable", gumjs_memory_access_monitor_enable, 0 },
  { "disable", gumjs_memory_access_monitor_disable, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_memory_init (GumDukMemory * self,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_memory_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct newproto ]
  duk_put_function_list (ctx, -1, gumjs_memory_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_new (ctx, 0);
  // [ newinstance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Memory");
  // []

  duk_push_c_function (ctx, gumjs_memory_access_monitor_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct newproto ]
  duk_put_function_list (ctx, -1, gumjs_memory_access_monitor_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_new (ctx, 0);
  // [ newinstance ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "MemoryAccessMonitor");
  // []
}

void
_gum_duk_memory_dispose (GumDukMemory * self)
{
  (void) self;
}

void
_gum_duk_memory_finalize (GumDukMemory * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_memory_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  GumDukCore * core = args->core;
  guint size, page_size;
  GumDukHeapPtr handle;

  if (!_gumjs_args_parse (ctx, "u", &size))
  {
    duk_push_null (ctx);
    return 1;
  }
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

  duk_push_heapptr (ctx, handle);
  return 1;

invalid_size:
  {
    _gumjs_throw (ctx, "invalid size");
    duk_push_null (ctx);
    return 1;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  GumDukCore * core = args->core;
  GumExceptor * exceptor = core->exceptor;
  gpointer destination, source;
  guint size;
  GumExceptorScope scope;

  if (!_gumjs_args_parse (ctx, "ppu", &destination, &source, &size))
  {
    duk_push_null (ctx);
    return 1;
  }
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
    _gumjs_throw_native (ctx, &scope.exception, core);
  }

beach:
  duk_push_undefined (ctx);
  return 1;

invalid_size:
  {
    _gumjs_throw (ctx, "invalid size");
    duk_push_null (ctx);
    return 1;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  guint size;
  GumPageProtection prot;
  gboolean success = TRUE;

  if (!_gumjs_args_parse (ctx, "pum", &address, &size, &prot))
  {
    duk_push_null (ctx);
    return 1;
  }
  if (size == 0)
    goto beach;
  else if (size > 0x7fffffff)
    goto invalid_size;

  success = gum_try_mprotect (address, size, prot);

beach:
  duk_push_boolean (ctx, success ? TRUE : FALSE);
  return 1;

invalid_size:
  {
    _gumjs_throw (ctx, "invalid size");
    duk_push_null (ctx);
    return 1;
  }
}

static int
gum_duk_memory_read (GumDukMemory * self,
                     GumMemoryValueType type,
                     const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumDukHeapPtr result = NULL;
  gpointer address;
  gint length = -1;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gumjs_args_parse (ctx, "pi", &address, &length))
      {
        duk_push_null (ctx);
        return 1;
      }
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gumjs_args_parse (ctx, "p|i", &address, &length))
      {
        duk_push_null (ctx);
        return 1;
      }
      break;
    default:
      if (!_gumjs_args_parse (ctx, "p", &address))
      {
        duk_push_null (ctx);
        return 1;
      }
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        duk_push_heapptr (ctx, _gumjs_native_pointer_new (ctx, *((gpointer *) address), core));
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
        duk_push_number (ctx, *((gint64 *) address));
        break;
      case GUM_MEMORY_VALUE_U64:
        duk_push_number (ctx, *((guint64 *) address));
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
          guint8 dummy_to_trap_bad_pointer_early;
          GumDukHeapPtr array;
          gpointer array_data;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          array = _gumjs_array_buffer_new (ctx, length, core);
          array_data = _gumjs_array_buffer_get_data (ctx, array, NULL);
          printf ("here!!!! length: %d\n", length);
          printf ("array_data: %p, data: %p, length: %d\n", array_data, data, length);
          memcpy (array_data, data, length);
          printf ("here!!!!\n");
          printf ("a[0] = %02x, a[1] = %02x\n", *(gchar *)array_data, *(gchar *)(array_data+1));
          duk_push_heapptr (ctx, array);
          _gumjs_duk_release_heapptr (ctx, array);
        }
        else
        {
          GumDukHeapPtr array = _gumjs_array_buffer_new (ctx, 0, core);
          duk_push_heapptr (ctx, array);
          _gumjs_duk_release_heapptr (ctx, array);
        }

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar * data;
        guint8 dummy_to_trap_bad_pointer_early;

        data = address;
        if (data == NULL)
        {
          duk_push_null (ctx);
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

        duk_push_string (ctx, data);

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
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        duk_push_string (ctx, str_utf8);
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
        _gumjs_throw (ctx, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (ctx, &scope.exception, core);
  }

  return 1;
}

static int
gum_duk_memory_write (GumDukMemory * self,
                      GumMemoryValueType type,
                      const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCore * core = self->core;
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
      if (!_gumjs_args_parse (ctx, "pp", &address, &pointer))
      {
        duk_push_null (ctx);
        return 1;
      }
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
      if (!_gumjs_args_parse (ctx, "pn", &address, &number))
      {
        duk_push_null (ctx);
        return 1;
      }
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gumjs_args_parse (ctx, "pB", &address, &bytes))
      {
        duk_push_null (ctx);
        return 1;
      }
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gumjs_args_parse (ctx, "ps", &address, &str))
      {
        duk_push_null (ctx);
        return 1;
      }
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
        _gumjs_throw (ctx, "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gumjs_throw_native (ctx, &scope.exception, core);
  }

  g_bytes_unref (bytes);
  g_free (str);
  g_free (str_utf16);
#ifdef G_OS_WIN32
  g_free (str_ansi);
#endif

  duk_push_undefined (ctx);
  return 1;
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
  GumDukHeapPtr handle;

  if (!_gumjs_args_parse (ctx, "s", &str))
  {
    duk_push_null (ctx);
    return 1;
  }
  str_ansi = gum_ansi_string_from_utf8 (str);
  g_free (str);

  _gumjs_native_resource_new (ctx, str_ansi, g_free, args->core, &handle);

  duk_push_heapptr (ctx, handle);
  return 1;
#else
  _gumjs_throw (ctx, "ANSI API is only applicable on Windows");
  duk_push_null (ctx);
  return 1;
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  gchar * str, * strdup;
  GumDukHeapPtr handle;

  if (!_gumjs_args_parse (ctx, "s", &str))
  {
    duk_push_null (ctx);
    return 1;
  }
  printf ("in alloc_utf8_string str: %p\n", str);

  strdup = g_strdup (str);
  printf ("in alloc_utf8_string str: %p\n", strdup);
  _gumjs_native_resource_new (ctx, strdup, g_free, args->core, &handle);

  duk_push_heapptr (ctx, handle);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  gchar * str;
  gunichar2 * str_utf16;
  GumDukHeapPtr handle;

  if (!_gumjs_args_parse (ctx, "s", &str))
  {
    duk_push_null (ctx);
    return 1;
  }
  str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

  _gumjs_native_resource_new (ctx, str_utf16, g_free, args->core, &handle);

  duk_push_heapptr (ctx, handle);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  GumDukCore * core = args->core;
  GumMemoryScanContext sc;
  gpointer address;
  guint size;
  gchar * match_str;

  if (!_gumjs_args_parse (ctx, "pusF{onMatch,onError?,onComplete}", &address,
      &size, &match_str, &sc.on_match, &sc.on_error, &sc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }

  sc.range.base_address = GUM_ADDRESS (address);
  sc.range.size = size;
  sc.pattern = gum_match_pattern_new_from_string (match_str);
  sc.core = core;

  if (sc.pattern == NULL)
    goto invalid_match_pattern;

  _gumjs_duk_protect (ctx, sc.on_match);
  if (sc.on_error != NULL)
    _gumjs_duk_protect (ctx, sc.on_error);
  _gumjs_duk_protect (ctx, sc.on_complete);

  _gum_duk_core_push_job (core,
      (GumScriptJobFunc) gum_memory_scan_context_run,
      g_slice_dup (GumMemoryScanContext, &sc),
      (GDestroyNotify) gum_memory_scan_context_free);

  duk_push_undefined (ctx);
  return 1;

invalid_match_pattern:
  {
    _gumjs_throw (ctx, "invalid match pattern");
    duk_push_null (ctx);
    return 1;
  }
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * ctx)
{
  duk_context * js_ctx = ctx->core->ctx;

  gum_match_pattern_free (ctx->pattern);

  _gumjs_duk_unprotect (js_ctx, ctx->on_match);
  if (ctx->on_error != NULL)
    _gumjs_duk_unprotect (js_ctx, ctx->on_error);
  _gumjs_duk_unprotect (js_ctx, ctx->on_complete);

  g_slice_free (GumMemoryScanContext, ctx);
}

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  GumDukCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope exceptor_scope;
  GumDukScope script_scope;
  duk_context * ctx = core->ctx;

  if (gum_exceptor_try (exceptor, &exceptor_scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        gum_memory_scan_context_emit_match, self);
  }

  _gum_duk_scope_enter (&script_scope, core);

  if (gum_exceptor_catch (exceptor, &exceptor_scope))
  {
    if (self->on_error != NULL)
    {
      gchar * message;

      duk_push_heapptr (ctx, self->on_error);

      message = gum_exception_details_to_string (&exceptor_scope.exception);
      duk_push_string (ctx, message);
      g_free (message);

      int res = duk_pcall (ctx, 1);
      if (res)
      {
        /* TODO: this should probably set the exception on the scope */
        printf ("Error occured while calling on_error\n");
      }

      duk_pop (ctx);

      _gum_duk_scope_flush (&script_scope);
    }
  }

  duk_push_heapptr (ctx, self->on_complete);
  int res = duk_pcall (ctx, 1);
  if (res)
  {
    /* TODO: this should probably set the exception on the scope */
    printf ("Error occured while calling on_complete\n");
  }
  duk_pop (ctx);

  _gum_duk_scope_leave (&script_scope);
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    gpointer user_data)
{
  GumMemoryScanContext * self = user_data;
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx = self->core->ctx;
  GumDukHeapPtr match_address;
  gboolean proceed;

  _gum_duk_scope_enter (&scope, core);

  duk_push_heapptr (ctx, self->on_match);

  match_address = _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
  duk_push_heapptr (ctx, match_address);
  _gumjs_duk_release_heapptr (ctx, match_address);
  duk_push_number (ctx, size);

  int res = duk_pcall (ctx, 1);
  if (res)
  {
    /* TODO: this should probably set the exception on the scope */
    printf ("Error occured while calling on_match\n");
  }

  proceed = TRUE;
  if (duk_is_string (ctx, -1))
  {
    proceed = strcmp (duk_get_string (ctx, -1), "stop") != 0;
  }

  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_memory_access_monitor_construct)
{
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
#ifdef G_OS_WIN32
# error Please add MemoryAccessMonitor to the JavaScriptCore runtime
#else
  _gumjs_throw (ctx,
      "MemoryAccessMonitor is only available on Windows for now");
  duk_push_null (ctx);
  return 1;
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
#ifdef G_OS_WIN32
# error Please add MemoryAccessMonitor to the JavaScriptCore runtime
#else
  _gumjs_throw (ctx,
      "MemoryAccessMonitor is only available on Windows for now");
  duk_push_null (ctx);
  return 1;
#endif
}
