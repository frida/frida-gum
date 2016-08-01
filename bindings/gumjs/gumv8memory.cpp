/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8memory.h"

#include "gumv8scope.h"

#include <string.h>
#include <wchar.h>
#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

#define GUM_MAX_JS_ARRAY_LENGTH (100 * 1024 * 1024)

using namespace v8;

typedef guint GumMemoryValueType;
typedef struct _GumMemoryScanContext GumMemoryScanContext;
typedef struct _GumMemoryScanSyncContext GumMemoryScanSyncContext;

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
  GumV8Core * core;
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumPersistent<Function>::type * on_match;
  GumPersistent<Function>::type * on_error;
  GumPersistent<Function>::type * on_complete;
};

struct _GumMemoryScanSyncContext
{
  GumV8Core * core;
  Isolate * isolate;
  Local<Array> matches;
};

static void gum_v8_memory_on_alloc (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_memory_on_alloc_ansi_string (
    const FunctionCallbackInfo<Value> & info);
#ifdef G_OS_WIN32
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif
static void gum_v8_memory_on_alloc_utf8_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_memory_on_alloc_utf16_string (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_memory_on_copy (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_memory_on_protect (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_memory_do_read (
    const FunctionCallbackInfo<Value> & info, GumMemoryValueType type);
static void gum_v8_memory_do_write (
    const FunctionCallbackInfo<Value> & info, GumMemoryValueType type);

static void gum_v8_memory_on_scan (
    const FunctionCallbackInfo<Value> & info);
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static void gum_v8_script_do_memory_scan (gpointer user_data);
static gboolean gum_v8_process_scan_match (GumAddress address, gsize size,
    gpointer user_data);

static void gum_v8_memory_on_scan_sync (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_process_sync_scan_match (GumAddress address, gsize size,
    gpointer user_data);

static void gum_v8_memory_access_monitor_on_enable (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_memory_access_monitor_on_disable (
    const FunctionCallbackInfo<Value> & info);
#ifdef G_OS_WIN32
static void gum_v8_script_handle_memory_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, gpointer user_data);
static gboolean gum_v8_memory_ranges_get (GumV8Memory * self,
    Handle<Value> value, GumMemoryRange ** ranges, guint * num_ranges);
static gboolean gum_v8_memory_range_get (GumV8Memory * self,
    Handle<Value> obj, GumMemoryRange * range);
#endif

#define GUM_DEFINE_MEMORY_READ(T) \
    static void \
    gum_v8_memory_on_read_##T (const FunctionCallbackInfo<Value> & info) \
    { \
      return gum_v8_memory_do_read (info, GUM_MEMORY_VALUE_##T); \
    }
#define GUM_DEFINE_MEMORY_WRITE(T) \
    static void \
    gum_v8_memory_on_write_##T (const FunctionCallbackInfo<Value> & info) \
    { \
      gum_v8_memory_do_write (info, GUM_MEMORY_VALUE_##T); \
    }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
    GUM_DEFINE_MEMORY_READ (T); \
    GUM_DEFINE_MEMORY_WRITE (T)

#define GUM_EXPORT_MEMORY_READ(N, T) \
    memory->Set (String::NewFromUtf8 (isolate, "read" N), \
        FunctionTemplate::New (isolate, gum_v8_memory_on_read_##T, data))
#define GUM_EXPORT_MEMORY_WRITE(N, T) \
    memory->Set (String::NewFromUtf8 (isolate, "write" N), \
        FunctionTemplate::New (isolate, gum_v8_memory_on_write_##T, data))
#define GUM_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUM_EXPORT_MEMORY_READ (N, T); \
    GUM_EXPORT_MEMORY_WRITE (N, T)

GUM_DEFINE_MEMORY_READ_WRITE (POINTER)
GUM_DEFINE_MEMORY_READ_WRITE (S8)
GUM_DEFINE_MEMORY_READ_WRITE (U8)
GUM_DEFINE_MEMORY_READ_WRITE (S16)
GUM_DEFINE_MEMORY_READ_WRITE (U16)
GUM_DEFINE_MEMORY_READ_WRITE (S32)
GUM_DEFINE_MEMORY_READ_WRITE (U32)
GUM_DEFINE_MEMORY_READ_WRITE (S64)
GUM_DEFINE_MEMORY_READ_WRITE (U64)
GUM_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUM_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ (C_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

void
_gum_v8_memory_init (GumV8Memory * self,
                         GumV8Core * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> memory = ObjectTemplate::New ();
  memory->Set (String::NewFromUtf8 (isolate, "alloc"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_alloc, data));
  memory->Set (String::NewFromUtf8 (isolate, "copy"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_copy, data));
  memory->Set (String::NewFromUtf8 (isolate, "protect"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_protect, data));

  GUM_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER);
  GUM_EXPORT_MEMORY_READ_WRITE ("S8", S8);
  GUM_EXPORT_MEMORY_READ_WRITE ("U8", U8);
  GUM_EXPORT_MEMORY_READ_WRITE ("S16", S16);
  GUM_EXPORT_MEMORY_READ_WRITE ("U16", U16);
  GUM_EXPORT_MEMORY_READ_WRITE ("S32", S32);
  GUM_EXPORT_MEMORY_READ_WRITE ("U32", U32);
  GUM_EXPORT_MEMORY_READ_WRITE ("S64", S64);
  GUM_EXPORT_MEMORY_READ_WRITE ("U64", U64);
  GUM_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT);
  GUM_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE);
  GUM_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY);
  GUM_EXPORT_MEMORY_READ ("CString", C_STRING);
  GUM_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING);
  GUM_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING);
  GUM_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING);

  memory->Set (String::NewFromUtf8 (isolate, "allocAnsiString"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_alloc_ansi_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "allocUtf8String"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_alloc_utf8_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "allocUtf16String"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_alloc_utf16_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "scan"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_scan,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "scanSync"),
      FunctionTemplate::New (isolate, gum_v8_memory_on_scan_sync,
          data));
  scope->Set (String::NewFromUtf8 (isolate, "Memory"), memory);

  Handle<ObjectTemplate> monitor = ObjectTemplate::New ();
  monitor->Set (String::NewFromUtf8 (isolate, "enable"),
      FunctionTemplate::New (isolate,
          gum_v8_memory_access_monitor_on_enable, data));
  monitor->Set (String::NewFromUtf8 (isolate, "disable"),
      FunctionTemplate::New (isolate,
          gum_v8_memory_access_monitor_on_disable, data));
  scope->Set (String::NewFromUtf8 (isolate, "MemoryAccessMonitor"), monitor);
}

void
_gum_v8_memory_realize (GumV8Memory * self)
{
  Isolate * isolate = self->core->isolate;

  self->base_key = new GumPersistent<String>::type (isolate,
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> ("base"),
          NewStringType::kNormal,
          -1).ToLocalChecked ());
  self->size_key = new GumPersistent<String>::type (isolate,
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> ("size"),
          NewStringType::kNormal,
          -1).ToLocalChecked ());
}

void
_gum_v8_memory_dispose (GumV8Memory * self)
{
  delete self->size_key;
  delete self->base_key;
  self->size_key = nullptr;
  self->base_key = nullptr;
}

void
_gum_v8_memory_finalize (GumV8Memory * self)
{
  if (self->monitor != NULL)
  {
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }
}

/*
 * Prototype:
 * Memory.alloc(size)
 *
 * Docs:
 * Allocate a chunk of memory
 *
 * Example:
 * TBW
 */
static void
gum_v8_memory_on_alloc (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gsize size;
  if (!_gum_v8_size_get (info[0], &size, self->core))
    return;
  if (size == 0 || size > 0x7fffffff)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "invalid size")));
    return;
  }

  GumV8NativeResource * res;
  gsize page_size = gum_query_page_size ();

  if (size < page_size)
  {
    res = _gum_v8_native_resource_new (g_malloc (size), size, g_free, self->core);
  }
  else
  {
    guint n = ((size + page_size - 1) & ~(page_size - 1)) / page_size;
    res = _gum_v8_native_resource_new (gum_alloc_n_pages (n, GUM_PAGE_RW),
        n * page_size, gum_free_pages, self->core);
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

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
static void
gum_v8_memory_on_alloc_ansi_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

#ifdef G_OS_WIN32
  String::Utf8Value str (info[0]);
  gchar * str_heap = gum_ansi_string_from_utf8 (*str);
  GumV8NativeResource * res = _gum_v8_native_resource_new (str_heap,
      strlen (str_heap), g_free, self->core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
#else
  isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
      "ANSI API is only applicable on Windows")));
#endif
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

static void
gum_v8_memory_on_alloc_utf8_string (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  const gchar * s = *str;
  guint size = str.length () + 1;
  GumV8NativeResource * res = _gum_v8_native_resource_new (g_memdup (s, size), size,
      g_free, self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *res->instance));
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
static void
gum_v8_memory_on_alloc_utf16_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  glong items_written;
  gunichar2 * str_heap = g_utf8_to_utf16 (*str, -1, NULL, &items_written, NULL);
  gsize size = (items_written + 1) * sizeof (gunichar2);
  GumV8NativeResource * res = _gum_v8_native_resource_new (str_heap, size, g_free,
      self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *res->instance));
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
static void
gum_v8_memory_on_copy (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  gpointer destination;
  if (!_gum_v8_native_pointer_get (info[0], &destination, core))
    return;

  gpointer source;
  if (!_gum_v8_native_pointer_get (info[1], &source, core))
    return;

  gsize size;
  if (!_gum_v8_size_get (info[2], &size, core))
    return;
  if (size == 0)
  {
    return;
  }
  else if (size > 0x7fffffff)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "invalid size")));
    return;
  }

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
static void
gum_v8_memory_on_protect (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, self->core))
    return;

  gsize size;
  if (!_gum_v8_size_get (info[1], &size, self->core))
    return;
  if (size == 0)
  {
    info.GetReturnValue ().Set (true);
    return;
  }
  else if (size > 0x7fffffff)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "invalid size")));
    return;
  }

  GumPageProtection prot;
  if (!_gum_v8_page_protection_get (info[2], &prot, self->core))
    return;

  gboolean success = gum_try_mprotect (address, size, prot);
  info.GetReturnValue ().Set (success ? true : false);
}

static void
gum_v8_memory_do_read (const FunctionCallbackInfo<Value> & info,
                       GumMemoryValueType type)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;
  Local<Value> result;

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, core))
    return;

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_v8_native_pointer_new (
            *static_cast<const gpointer *> (address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (isolate, *static_cast<const gint8 *> (address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (isolate,
            *static_cast<const guint8 *> (address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (isolate, *static_cast<const gint16 *> (address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (isolate,
            *static_cast<const guint16 *> (address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (isolate, *static_cast<const gint32 *> (address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (isolate,
            *static_cast<const guint32 *> (address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_v8_int64_new (
            *static_cast<const gint64 *> (address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_v8_uint64_new (
            *static_cast<const guint64 *> (address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = Number::New (isolate, *static_cast<const gfloat *> (address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = Number::New (isolate,
            *static_cast<const gdouble *> (address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        if (info.Length () < 2)
        {
          isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
              isolate, "expected address and length")));
          break;
        }

        const guint8 * data = static_cast<const guint8 *> (address);
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        gsize size;
        if (!_gum_v8_size_get (info[1], &size, core))
          break;

        if (size > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          result = ArrayBuffer::New (isolate, g_memdup (data, size), size,
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
        const char * data = static_cast<const char *> (address);
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        gssize length = -1;
        if (info.Length () > 1 && !_gum_v8_ssize_get (info[1], &length, core))
          break;
        if (length < 0)
          length = strlen (data);

        if (length != 0)
        {
          result = String::NewFromOneByte (isolate,
              reinterpret_cast<const uint8_t *> (data), NewStringType::kNormal,
              length).ToLocalChecked ();
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const char * data = static_cast<const char *> (address);
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        gssize size = -1;
        if (info.Length () > 1 && !_gum_v8_ssize_get (info[1], &size, core))
          break;
        if (size < 0)
          size = strlen (data);

        if (size != 0)
        {
          result = String::NewFromUtf8 (isolate, data, String::kNormalString,
              size);
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        const gunichar2 * str_utf16 = static_cast<const gunichar2 *> (address);
        guint8 dummy_to_trap_bad_pointer_early;
        gchar * str_utf8;
        gssize length;
        glong size;

        if (str_utf16 == NULL)
        {
          result = Null (isolate);
          break;
        }

        memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        length = -1;
        if (info.Length () > 1 && !_gum_v8_ssize_get (info[1], &length, core))
          break;
        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);

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
        const char * str_ansi = static_cast<const char *> (address);
        if (str_ansi == NULL)
        {
          result = Null (isolate);
          break;
        }

        gssize length = -1;
        if (info.Length () > 1 && !_gum_v8_ssize_get (info[1], &length, core))
          break;

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          gchar * str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          int size = g_utf8_offset_to_pointer (str_utf8,
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
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "ANSI API is only applicable on Windows")));
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
      info.GetReturnValue ().Set (result);
  }
}

static void
gum_v8_memory_do_write (const FunctionCallbackInfo<Value> & info,
                        GumMemoryValueType type)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, core))
    return;

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
      {
        gpointer value;
        if (_gum_v8_native_pointer_get (info[1], &value, core))
          *static_cast<gpointer *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_S8:
      {
        gssize value;
        if (_gum_v8_ssize_get (info[1], &value, core))
          *static_cast<gint8 *> (address) = (gint8) value;
        break;
      }
      case GUM_MEMORY_VALUE_U8:
      {
        gsize value;
        if (_gum_v8_size_get (info[1], &value, core))
          *static_cast<guint8 *> (address) = (guint8) value;
        break;
      }
      case GUM_MEMORY_VALUE_S16:
      {
        gssize value;
        if (_gum_v8_ssize_get (info[1], &value, core))
          *static_cast<gint16 *> (address) = (gint16) value;
        break;
      }
      case GUM_MEMORY_VALUE_U16:
      {
        gsize value;
        if (_gum_v8_size_get (info[1], &value, core))
          *static_cast<guint16 *> (address) = (guint16) value;
        break;
      }
      case GUM_MEMORY_VALUE_S32:
      {
        gssize value;
        if (_gum_v8_ssize_get (info[1], &value, core))
          *static_cast<gint32 *> (address) = (gint32) value;
        break;
      }
      case GUM_MEMORY_VALUE_U32:
      {
        gsize value;
        if (_gum_v8_size_get (info[1], &value, core))
          *static_cast<guint32 *> (address) = (guint32) value;
        break;
      }
      case GUM_MEMORY_VALUE_S64:
      {
        gint64 value;
        if (_gum_v8_int64_get (info[1], &value, core))
          *static_cast<gint64 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U64:
      {
        guint64 value;
        if (_gum_v8_uint64_get (info[1], &value, core))
          *static_cast<guint64 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_FLOAT:
      {
        gfloat value = info[1]->NumberValue ();
        *static_cast<gfloat *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_DOUBLE:
      {
        gdouble value = info[1]->NumberValue ();
        *static_cast<gdouble *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        if (info.Length () < 2)
        {
          isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
              isolate, "expected address and data")));
          break;
        }

        Local<Value> value = info[1];
        if (value->IsArrayBuffer ())
        {
          ArrayBuffer::Contents contents =
              Handle<ArrayBuffer>::Cast (value)->GetContents ();

          memcpy (address, contents.Data (), contents.ByteLength ());
        }
        else if (value->IsArray ())
        {
          Handle<Array> array = Handle<Array>::Cast (value);

          uint32_t length = array->Length ();
          if (length <= GUM_MAX_JS_ARRAY_LENGTH)
          {
            for (uint32_t i = 0; i != length; i++)
            {
              uint32_t element = array->Get (i)->ToUint32 ()->Uint32Value ();
              static_cast<char *> (address)[i] = element;
            }
          }
          else
          {
            isolate->ThrowException (Exception::TypeError (
                String::NewFromUtf8 (isolate, "invalid array length")));
          }
        }
        else
        {
          isolate->ThrowException (Exception::TypeError (
              String::NewFromUtf8 (isolate, "expected array")));
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gchar dummy_to_trap_bad_pointer_early = '\0';
        memcpy (address, &dummy_to_trap_bad_pointer_early, sizeof (gchar));

        String::Utf8Value str (info[1]);
        const gchar * s = *str;
        int size = g_utf8_offset_to_pointer (s, g_utf8_strlen (s, -1)) - s;
        memcpy (static_cast<char *> (address), s, size + 1);
        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gunichar2 dummy_to_trap_bad_pointer_early = 0;
        memcpy (address, &dummy_to_trap_bad_pointer_early, sizeof (gunichar2));

        String::Value str (info[1]);
        const uint16_t * s = *str;
        int size = (str.length () + 1) * sizeof (uint16_t);
        memcpy (static_cast<char *> (address), s, size);
        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef G_OS_WIN32
        gchar dummy_to_trap_bad_pointer_early = '\0';
        memcpy (address, &dummy_to_trap_bad_pointer_early, sizeof (gchar));

        String::Utf8Value str (info[1]);
        gchar * str_ansi = gum_ansi_string_from_utf8 (*str);
        strcpy (static_cast<char *> (address), str_ansi);
        g_free (str_ansi);
#else
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "ANSI API is only applicable on Windows")));
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
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

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
static void
gum_v8_memory_on_scan (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, core))
    return;
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  if (!_gum_v8_size_get (info[1], &range.size, core))
    return;

  String::Utf8Value match_str (info[2]);

  Local<Value> callbacks_value = info[3];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Memory.scan: fourth argument must be a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  Local<Function> on_match;
  if (!_gum_v8_callbacks_get (callbacks, "onMatch", &on_match, core))
    return;
  Local<Function> on_error;
  if (!_gum_v8_callbacks_get_opt (callbacks, "onError", &on_error, core))
    return;
  Local<Function> on_complete;
  if (!_gum_v8_callbacks_get (callbacks, "onComplete", &on_complete, core))
    return;

  GumMatchPattern * pattern = gum_match_pattern_new_from_string (*match_str);
  if (pattern != NULL)
  {
    GumMemoryScanContext * ctx = g_slice_new0 (GumMemoryScanContext);

    ctx->core = core;
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = new GumPersistent<Function>::type (isolate, on_match);
    if (!on_error.IsEmpty ())
      ctx->on_error = new GumPersistent<Function>::type (isolate, on_error);
    ctx->on_complete = new GumPersistent<Function>::type (isolate, on_complete);

    _gum_v8_core_pin (core);
    _gum_v8_core_push_job (core, gum_v8_script_do_memory_scan, ctx,
        reinterpret_cast<GDestroyNotify> (gum_memory_scan_context_free));
  }
  else
  {
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        "invalid match pattern")));
  }
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * ctx)
{
  GumV8Core * core = ctx->core;

  gum_match_pattern_free (ctx->pattern);

  {
    ScriptScope script_scope (core->script);

    delete ctx->on_match;
    delete ctx->on_error;
    delete ctx->on_complete;

    _gum_v8_core_unpin (core);
  }

  g_slice_free (GumMemoryScanContext, ctx);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_v8_script_do_memory_scan (gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  GumV8Core * core = ctx->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    gum_memory_scan (&ctx->range, ctx->pattern, gum_v8_process_scan_match,
        ctx);
  }

  {
    ScriptScope script_scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> receiver (Undefined (isolate));

    if (gum_exceptor_catch (exceptor, &scope))
    {
      if (ctx->on_error != NULL)
      {
        gchar * message = gum_exception_details_to_string (&scope.exception);
        Local<Function> on_error (Local<Function>::New (isolate,
            *ctx->on_error));
        Handle<Value> argv[] = { String::NewFromUtf8 (isolate, message) };
        on_error->Call (receiver, 1, argv);
        g_free (message);
      }
    }

    Local<Function> on_complete (Local<Function>::New (isolate,
        *ctx->on_complete));
    on_complete->Call (receiver, 0, 0);
  }
}

static gboolean
gum_v8_process_scan_match (GumAddress address,
                           gsize size,
                           gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  ScriptScope scope (ctx->core->script);
  Isolate * isolate = ctx->core->isolate;

  Local<Function> on_match (Local<Function>::New (isolate, *ctx->on_match));
  Local<Value> receiver (Undefined (isolate));
  Handle<Value> argv[] = {
    _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), ctx->core),
    Integer::NewFromUnsigned (isolate, size)
  };
  Local<Value> result = on_match->Call (receiver, 2, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
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
static void
gum_v8_memory_on_scan_sync (const FunctionCallbackInfo<Value> & info)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;
  Isolate * isolate = core->isolate;

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, core))
    return;
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  if (!_gum_v8_size_get (info[1], &range.size, core))
    return;

  String::Utf8Value match_str (info[2]);

  GumMatchPattern * pattern = gum_match_pattern_new_from_string (*match_str);
  if (pattern == NULL)
  {
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        "invalid match pattern")));
    return;
  }

  GumMemoryScanSyncContext ctx;
  ctx.core = core;
  ctx.isolate = isolate;
  ctx.matches = Array::New (isolate);

  if (gum_exceptor_try (exceptor, &scope))
  {
    gum_memory_scan (&range, pattern, gum_v8_process_sync_scan_match, &ctx);
  }

  gum_match_pattern_free (pattern);

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
  else
  {
    info.GetReturnValue ().Set (ctx.matches);
  }
}

static gboolean
gum_v8_process_sync_scan_match (GumAddress address,
                                gsize size,
                                gpointer user_data)
{
  GumMemoryScanSyncContext * ctx =
      static_cast<GumMemoryScanSyncContext *> (user_data);
  GumV8Core * core = ctx->core;
  Isolate * isolate = ctx->isolate;

  Local<Object> match (Object::New (isolate));
  _gum_v8_object_set_pointer (match, "address", address, core);
  _gum_v8_object_set_uint (match, "size", size, core);
  Maybe<bool> success =
      ctx->matches->Set (isolate->GetCurrentContext (), ctx->matches->Length (),
      match);
  g_assert (success.IsJust ());

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
static void
gum_v8_memory_access_monitor_on_enable (
    const FunctionCallbackInfo<Value> & info)
{
#ifdef G_OS_WIN32
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = info.GetIsolate ();

  GumMemoryRange * ranges;
  guint num_ranges;
  if (!gum_v8_memory_ranges_get (self, info[0], &ranges, &num_ranges))
    return;

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "MemoryAccessMonitor.enable: second argument must be a callback "
        "object")));
    return;
  }
  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  Local<Function> on_access;
  if (!_gum_v8_callbacks_get (callbacks, "onAccess", &on_access, core))
  {
    g_free (ranges);
    return;
  }

  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  self->monitor = gum_memory_access_monitor_new (ranges, num_ranges,
      GUM_PAGE_RWX, TRUE, gum_v8_script_handle_memory_access, self, NULL);

  g_free (ranges);

  delete self->on_access;
  self->on_access = new GumPersistent<Function>::type (isolate, on_access);

  GError * error = NULL;
  if (!gum_memory_access_monitor_enable (self->monitor, &error))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        error->message)));
    g_error_free (error);

    delete self->on_access;
    self->on_access = nullptr;

    g_object_unref (self->monitor);
    self->monitor = NULL;
  }
#else
  Isolate * isolate = info.GetIsolate ();

  isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
      "MemoryAccessMonitor is only available on Windows for now")));
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
static void
gum_v8_memory_access_monitor_on_disable (
    const FunctionCallbackInfo<Value> & info)
{
#ifdef G_OS_WIN32
  GumV8Memory * self = static_cast<GumV8Memory *> (
      info.Data ().As<External> ()->Value ());

  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  delete self->on_access;
  self->on_access = nullptr;
#else
  Isolate * isolate = info.GetIsolate ();

  isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
      "MemoryAccessMonitor is only available on Windows for now")));
#endif
}

#ifdef G_OS_WIN32

static void
gum_v8_script_handle_memory_access (GumMemoryAccessMonitor * monitor,
                                    const GumMemoryAccessDetails * details,
                                    gpointer user_data)
{
  GumV8Memory * self = static_cast<GumV8Memory *> (user_data);
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;
  Local<Context> context = isolate->GetCurrentContext ();
  ScriptScope script_scope (core->script);

  (void) monitor;

  Local<Object> d (Object::New (isolate));
  _gum_v8_object_set_ascii (d, "operation",
      _gum_v8_memory_operation_to_string (details->operation), core);
  _gum_v8_object_set_pointer (d, "from", details->from, core);
  _gum_v8_object_set_pointer (d, "address", details->address, core);

  _gum_v8_object_set_uint (d, "rangeIndex", details->range_index, core);
  _gum_v8_object_set_uint (d, "pageIndex", details->page_index, core);
  _gum_v8_object_set_uint (d, "pagesCompleted", details->pages_completed, core);
  _gum_v8_object_set_uint (d, "pagesTotal", details->pages_total, core);

  Local<Function> on_access (Local<Function>::New (isolate, *self->on_access));
  Handle<Value> argv[] = {
    d
  };
  MaybeLocal<Value> result =
      on_access->Call (context, Null (isolate), 1, argv);
  (void) result;
}

static gboolean
gum_v8_memory_ranges_get (GumV8Memory * self,
                          Handle<Value> value,
                          GumMemoryRange ** ranges,
                          guint * num_ranges)
{
  Isolate * isolate = self->core->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  if (value->IsArray ())
  {
    Local<Array> array = Handle<Array>::Cast (value);

    uint32_t length = array->Length ();
    if (length == 0 || length > 1024)
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "expected one or more range objects")));
      return FALSE;
    }

    GumMemoryRange * result = g_new (GumMemoryRange, length);
    for (uint32_t i = 0; i != length; i++)
    {
      Local<Value> range = array->Get (context, i).ToLocalChecked ();
      if (!gum_v8_memory_range_get (self, range, &result[i]))
      {
        g_free (result);
        return FALSE;
      }
    }
    *ranges = result;
    *num_ranges = length;
    return TRUE;
  }
  else if (value->IsObject ())
  {
    Local<Object> obj = Handle<Object>::Cast (value);

    GumMemoryRange * result = g_new (GumMemoryRange, 1);
    if (gum_v8_memory_range_get (self, obj, result))
    {
      *ranges = result;
      *num_ranges = 1;
      return TRUE;
    }
    else
    {
      g_free (result);
      return FALSE;
    }
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected a range object or an array of range objects")));
    return FALSE;
  }
}

static gboolean
gum_v8_memory_range_get (GumV8Memory * self,
                         Handle<Value> value,
                         GumMemoryRange * range)
{
  GumV8Core * core = self->core;
  Isolate * isolate = self->core->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  if (!value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected a range object")));
    return FALSE;
  }
  Local<Object> obj = Handle<Object>::Cast (value);

  Local<String> base_key (Local<String>::New (isolate, *self->base_key));
  Local<Value> base_val = obj->Get (context, base_key).ToLocalChecked ();
  gpointer base;
  if (!_gum_v8_native_pointer_get (base_val, &base, core))
    return FALSE;

  Local<String> size_key (Local<String>::New (isolate, *self->size_key));
  Local<Value> size_val = obj->Get (context, size_key).ToLocalChecked ();
  if (!size_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "memory range has invalid or missing size property")));
    return FALSE;
  }
  Local<Number> size = Local<Number>::Cast (size_val);

  range->base_address = GUM_ADDRESS (base);
  range->size = size->Uint32Value ();

  return TRUE;
}

#endif

