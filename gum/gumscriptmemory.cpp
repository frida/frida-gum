/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptmemory.h"

#include "gumscriptscope.h"
#include "gumtls.h"
#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#endif

#include <string>
#include <malloc/malloc.h>
#include <gio/gio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# define GUM_SETJMP(env) setjmp (env)
# define GUM_LONGJMP(env, val) longjmp (env, val)
  typedef jmp_buf gum_jmp_buf;
#else
# include <signal.h>
# ifdef HAVE_DARWIN
#  define GUM_SETJMP(env) setjmp (env)
#  define GUM_LONGJMP(env, val) longjmp (env, val)
   typedef jmp_buf gum_jmp_buf;
# else
#  define GUM_SETJMP(env) sigsetjmp (env, 1)
#  define GUM_LONGJMP(env, val) siglongjmp (env, val)
   typedef sigjmp_buf gum_jmp_buf;
# endif
#endif

#define GUM_MAX_JS_ARRAY_LENGTH (100 * 1024 * 1024)

using namespace v8;

typedef struct _GumMemoryAccessScope GumMemoryAccessScope;
typedef guint GumMemoryValueType;
typedef struct _GumMemoryScanContext GumMemoryScanContext;

struct _GumMemoryAccessScope
{
  gboolean exception_occurred;
  gpointer address;
  gum_jmp_buf env;
};
#define GUM_MEMORY_ACCESS_SCOPE_INIT { FALSE, NULL, }

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
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_STL_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct _GumMemoryScanContext
{
  GumScriptCore * core;
  GumMemoryRange range;
  GumMatchPattern * pattern;
  GumPersistent<Function>::type * on_match;
  GumPersistent<Function>::type * on_error;
  GumPersistent<Function>::type * on_complete;
  GumPersistent<Value>::type * receiver;
};

static void gum_script_memory_on_alloc (
    const FunctionCallbackInfo<Value> & info);
#ifdef G_OS_WIN32
static void gum_script_memory_on_alloc_ansi_string (
    const FunctionCallbackInfo<Value> & info);
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif
static void gum_script_memory_on_alloc_utf8_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_memory_on_alloc_utf16_string (
    const FunctionCallbackInfo<Value> & info);

static void gum_script_memory_on_alloc_stl_string (
    const FunctionCallbackInfo<Value> & info);

static void gum_script_memory_on_copy (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_memory_on_protect (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_memory_do_read (
    const FunctionCallbackInfo<Value> & info, GumMemoryValueType type);
static void gum_script_memory_do_write (
    const FunctionCallbackInfo<Value> & info, GumMemoryValueType type);

static void gum_script_memory_on_scan (
    const FunctionCallbackInfo<Value> & info);
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static void gum_script_do_memory_scan (gpointer user_data);
static gboolean gum_script_process_scan_match (GumAddress address, gsize size,
    gpointer user_data);

#ifdef G_OS_WIN32
static gboolean gum_script_memory_on_exception (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);
#else
static void gum_script_memory_on_invalid_access (int sig, siginfo_t * siginfo,
    void * context);
#endif

G_LOCK_DEFINE_STATIC (gum_memaccess);
static guint gum_memaccess_refcount = 0;
static GumTlsKey gum_memaccess_scope_tls;
#ifndef G_OS_WIN32
static struct sigaction gum_memaccess_old_sigsegv;
static struct sigaction gum_memaccess_old_sigbus;
#endif

#define GUM_DEFINE_MEMORY_READ(T) \
    static void \
    gum_script_memory_on_read_##T (const FunctionCallbackInfo<Value> & info) \
    { \
      return gum_script_memory_do_read (info, GUM_MEMORY_VALUE_##T); \
    }
#define GUM_DEFINE_MEMORY_WRITE(T) \
    static void \
    gum_script_memory_on_write_##T (const FunctionCallbackInfo<Value> & info) \
    { \
      gum_script_memory_do_write (info, GUM_MEMORY_VALUE_##T); \
    }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
    GUM_DEFINE_MEMORY_READ (T); \
    GUM_DEFINE_MEMORY_WRITE (T)

#define GUM_EXPORT_MEMORY_READ(N, T) \
    memory->Set (String::NewFromUtf8 (isolate, "read" N), \
        FunctionTemplate::New (isolate, gum_script_memory_on_read_##T, data))
#define GUM_EXPORT_MEMORY_WRITE(N, T) \
    memory->Set (String::NewFromUtf8 (isolate, "write" N), \
        FunctionTemplate::New (isolate, gum_script_memory_on_write_##T, data))
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
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUM_DEFINE_MEMORY_READ (STL_STRING)

#ifdef G_OS_WIN32
GUM_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)
#endif

void
_gum_script_memory_init (GumScriptMemory * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> memory = ObjectTemplate::New ();
  memory->Set (String::NewFromUtf8 (isolate, "alloc"),
      FunctionTemplate::New (isolate, gum_script_memory_on_alloc, data));
  memory->Set (String::NewFromUtf8 (isolate, "copy"),
      FunctionTemplate::New (isolate, gum_script_memory_on_copy, data));
  memory->Set (String::NewFromUtf8 (isolate, "protect"),
      FunctionTemplate::New (isolate, gum_script_memory_on_protect, data));

  GUM_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER);
  GUM_EXPORT_MEMORY_READ_WRITE ("S8", S8);
  GUM_EXPORT_MEMORY_READ_WRITE ("U8", U8);
  GUM_EXPORT_MEMORY_READ_WRITE ("S16", S16);
  GUM_EXPORT_MEMORY_READ_WRITE ("U16", U16);
  GUM_EXPORT_MEMORY_READ_WRITE ("S32", S32);
  GUM_EXPORT_MEMORY_READ_WRITE ("U32", U32);
  GUM_EXPORT_MEMORY_READ_WRITE ("S64", S64);
  GUM_EXPORT_MEMORY_READ_WRITE ("U64", U64);
  GUM_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY);
  GUM_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING);

  GUM_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING);
  GUM_EXPORT_MEMORY_READ("StlString", STL_STRING);
#ifdef G_OS_WIN32
  GUM_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING);

  memory->Set (String::NewFromUtf8 (isolate, "allocAnsiString"),
      FunctionTemplate::New (isolate, gum_script_memory_on_alloc_ansi_string,
          data));
#endif
  memory->Set (String::NewFromUtf8 (isolate, "allocUtf8String"),
      FunctionTemplate::New (isolate, gum_script_memory_on_alloc_utf8_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "allocUtf16String"),
      FunctionTemplate::New (isolate, gum_script_memory_on_alloc_utf16_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "allocStlString"),
      FunctionTemplate::New (isolate, gum_script_memory_on_alloc_stl_string,
          data));
  memory->Set (String::NewFromUtf8 (isolate, "scan"),
      FunctionTemplate::New (isolate, gum_script_memory_on_scan,
          data));
  scope->Set (String::NewFromUtf8 (isolate, "Memory"), memory);

  G_LOCK (gum_memaccess);
  if (gum_memaccess_refcount++ == 0)
  {
    GUM_TLS_KEY_INIT (&gum_memaccess_scope_tls);

#ifndef G_OS_WIN32
    struct sigaction action;
    action.sa_sigaction = gum_script_memory_on_invalid_access;
    sigemptyset (&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    sigaction (SIGSEGV, &action, &gum_memaccess_old_sigsegv);
    sigaction (SIGBUS, &action, &gum_memaccess_old_sigbus);
#endif
  }
  G_UNLOCK (gum_memaccess);

#ifdef G_OS_WIN32
  gum_win_exception_hook_add (gum_script_memory_on_exception, self);
#endif
}

void
_gum_script_memory_realize (GumScriptMemory * self)
{
  Isolate * isolate = self->core->isolate;

  self->length_key = new GumPersistent<String>::type (isolate,
      String::NewFromUtf8 (isolate, "length"));
}

void
_gum_script_memory_dispose (GumScriptMemory * self)
{
  delete self->length_key;
  self->length_key = NULL;
}

void
_gum_script_memory_finalize (GumScriptMemory * self)
{
  (void) self;

#ifdef G_OS_WIN32
  gum_win_exception_hook_remove (gum_script_memory_on_exception, self);
#endif

  G_LOCK (gum_memaccess);
  if (--gum_memaccess_refcount == 0)
  {
#ifndef G_OS_WIN32
    sigaction (SIGSEGV, &gum_memaccess_old_sigsegv, NULL);
    memset (&gum_memaccess_old_sigsegv, 0, sizeof (gum_memaccess_old_sigsegv));
    sigaction (SIGBUS, &gum_memaccess_old_sigbus, NULL);
    memset (&gum_memaccess_old_sigbus, 0, sizeof (gum_memaccess_old_sigbus));
#endif

    GUM_TLS_KEY_FREE (gum_memaccess_scope_tls);
    gum_memaccess_scope_tls = 0;
  }
  G_UNLOCK (gum_memaccess);
}

static void
gum_script_memory_on_alloc (const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  uint32_t size = info[0]->Uint32Value ();
  if (size == 0 || size > 0x7fffffff)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "invalid size")));
    return;
  }

  GumHeapBlock * block = _gum_heap_block_new (g_malloc (size), size,
      self->core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *block->instance));
}

#ifdef G_OS_WIN32

static void
gum_script_memory_on_alloc_ansi_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  gchar * str_heap = gum_ansi_string_from_utf8 (*str);
  GumHeapBlock * block = _gum_heap_block_new (str_heap, strlen (str_heap),
      self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *block->instance));
}

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
gum_script_memory_on_alloc_utf8_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  const gchar * s = *str;
  guint size = (g_utf8_offset_to_pointer (s, str.length ()) - s) + 1;
  GumHeapBlock * block = _gum_heap_block_new (g_memdup (s, size), size,
      self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *block->instance));
}

static void
gum_script_memory_on_alloc_utf16_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  glong items_written;
  gunichar2 * str_heap = g_utf8_to_utf16 (*str, -1, NULL, &items_written, NULL);
  gsize size = (items_written + 1) * sizeof (gunichar2);
  GumHeapBlock * block = _gum_heap_block_new (str_heap, size, self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *block->instance));
}

static void
gum_script_memory_on_alloc_stl_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());

  String::Utf8Value str (info[0]);
  const gchar * s = *str;
  std::string *stl_str = new std::string (s);

  guint size = malloc_size ((void *)stl_str);

  GumHeapBlock * block = _gum_heap_block_new (stl_str, size,
      self->core);
  info.GetReturnValue ().Set (
      Local<Object>::New (self->core->isolate, *block->instance));
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_script_memory_on_copy (const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  gpointer to;
  if (!_gum_script_pointer_get (info[0], &to, self->core))
    return;

  gpointer from;
  if (!_gum_script_pointer_get (info[1], &from, self->core))
    return;

  uint32_t size = info[2]->Uint32Value ();
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

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    memcpy (to, from, size);
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  if (scope.exception_occurred)
  {
    gchar * message = g_strdup_printf (
        "access violation accessing 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        message)));
    g_free (message);
  }
}

static void
gum_script_memory_on_protect (const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gpointer address;
  if (!_gum_script_pointer_get (info[0], &address, self->core))
    return;

  gsize size = info[1]->Uint32Value ();
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

  GumPageProtection prot;
  if (!_gum_script_page_protection_get (info[2], &prot, self->core))
    return;

  gboolean success = gum_try_mprotect (address, size, prot);
  info.GetReturnValue ().Set (success ? true : false);
}

static void
gum_script_memory_do_read (const FunctionCallbackInfo<Value> & info,
                           GumMemoryValueType type)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;
  Local<Value> result;

  gpointer address;
  if (!_gum_script_pointer_get (info[0], &address, self->core))
    return;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_script_pointer_new (
            *static_cast<const gpointer *> (address), self->core);
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
        result = Number::New (isolate, *static_cast<const gint64 *> (address));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = Number::New (isolate, *static_cast<const guint64 *> (address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = static_cast<const guint8 *> (address);
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        gpointer data_copy = NULL;
        int64_t size = info[1]->IntegerValue ();
        if (size > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          data_copy = g_memdup (data, size);
        }

        GumByteArray * arr = _gum_byte_array_new (data_copy, size, self->core);
        result = Local<Object>::New (isolate, *arr->instance);
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

        int64_t length = -1;
        if (info.Length () > 1)
          length = info[1]->IntegerValue();
        if (length < 0)
          length = g_utf8_strlen (data, -1);

        if (length != 0)
        {
          int size = g_utf8_offset_to_pointer (data, length) - data;
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
        glong length, size;

        if (str_utf16 == NULL)
        {
          result = Null (isolate);
          break;
        }

        memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        length = (info.Length () > 1) ? info[1]->IntegerValue () : -1;
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
      case GUM_MEMORY_VALUE_STL_STRING:
      {
        std::string * data = reinterpret_cast<std::string *> (address);
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        int64_t length = -1;
        if (info.Length () > 1)
          length = info[1]->IntegerValue();
        if (length < 0)
          length = data->length();

        if (length != 0)
        {
          result = String::NewFromUtf8 (isolate, data->c_str(), String::kNormalString,
              length);
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
#ifdef G_OS_WIN32
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
        const char * str_ansi = static_cast<const char *> (address);
        if (str_ansi == NULL)
        {
          result = Null (isolate);
          break;
        }

        int64_t length = -1;
        if (info.Length () > 1)
          length = info[1]->IntegerValue();

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

        break;
      }
#endif
      default:
        g_assert_not_reached ();
    }
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  if (!scope.exception_occurred)
  {
    info.GetReturnValue ().Set (result);
  }
  else
  {
    gchar * message = g_strdup_printf (
        "access violation reading 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        message)));
    g_free (message);
  }
}

static void
gum_script_memory_do_write (const FunctionCallbackInfo<Value> & info,
                            GumMemoryValueType type)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  gpointer address;
  if (!_gum_script_pointer_get (info[0], &address, self->core))
    return;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
      {
        gpointer value;
        if (_gum_script_pointer_get (info[1], &value, self->core))
          *static_cast<gpointer *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_S8:
      {
        gint8 value = info[1]->Int32Value ();
        *static_cast<gint8 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U8:
      {
        guint8 value = info[1]->Uint32Value ();
        *static_cast<guint8 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_S16:
      {
        gint16 value = info[1]->Int32Value ();
        *static_cast<gint16 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U16:
      {
        guint16 value = info[1]->Uint32Value ();
        *static_cast<guint16 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_S32:
      {
        gint32 value = info[1]->Int32Value ();
        *static_cast<gint32 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U32:
      {
        guint32 value = info[1]->Uint32Value ();
        *static_cast<guint32 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_S64:
      {
        gint64 value = info[1]->IntegerValue ();
        *static_cast<gint64 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U64:
      {
        guint64 value = info[1]->IntegerValue ();
        *static_cast<guint64 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        Local<Object> array = info[1].As <Object> ();
        if (array->HasIndexedPropertiesInExternalArrayData () &&
            array->GetIndexedPropertiesExternalArrayDataType ()
            == kExternalUint8Array)
        {
          const guint8 * data = static_cast<guint8 *> (
              array->GetIndexedPropertiesExternalArrayData ());
          int data_length =
              array->GetIndexedPropertiesExternalArrayDataLength ();
          memcpy (address, data, data_length);
        }
        else
        {
          Local<String> length_key (Local<String>::New (isolate,
              *self->length_key));
          if (array->Has (length_key))
          {
            uint32_t length = array->Get (length_key)->Uint32Value ();
            if (length <= GUM_MAX_JS_ARRAY_LENGTH)
            {
              for (uint32_t i = 0; i != length; i++)
              {
                uint32_t value = array->Get (i)->ToUint32 ()->Uint32Value ();
                static_cast<char *> (address)[i] = value;
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
#ifdef G_OS_WIN32
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
        gchar dummy_to_trap_bad_pointer_early = '\0';
        memcpy (address, &dummy_to_trap_bad_pointer_early, sizeof (gchar));

        String::Utf8Value str (info[1]);
        gchar * str_ansi = gum_ansi_string_from_utf8 (*str);
        strcpy (static_cast<char *> (address), str_ansi);
        g_free (str_ansi);

        break;
      }
#endif
      default:
        g_assert_not_reached ();
    }
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  if (scope.exception_occurred)
  {
    gchar * message = g_strdup_printf (
        "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        message)));
    g_free (message);
  }

  return;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

#ifdef G_OS_WIN32

static void
gum_script_memory_do_longjmp (gum_jmp_buf * env)
{
  GUM_LONGJMP (*env, 1);
}

static gboolean
gum_script_memory_on_exception (EXCEPTION_RECORD * exception_record,
                                CONTEXT * context,
                                gpointer user_data)
{
  GumMemoryAccessScope * scope;

  (void) user_data;

  if (exception_record->ExceptionCode != STATUS_ACCESS_VIOLATION)
    return FALSE;

  /* must be a READ or WRITE */
  if (exception_record->ExceptionInformation[0] > 1)
    return FALSE;

  scope = (GumMemoryAccessScope *)
      GUM_TLS_KEY_GET_VALUE (gum_memaccess_scope_tls);
  if (scope == NULL)
    return FALSE;

  if (!scope->exception_occurred)
  {
    scope->exception_occurred = TRUE;

    scope->address = (gpointer) exception_record->ExceptionInformation[1];

#if GLIB_SIZEOF_VOID_P == 4
    context->Esp -= 8;
    *((gum_jmp_buf **) (context->Esp + 4)) = &scope->env;
    *((gum_jmp_buf **) (context->Esp + 0)) = NULL;
    context->Eip = (DWORD) gum_script_memory_do_longjmp;
#else
    context->Rsp -= 16;
    context->Rcx = (DWORD64) &scope->env;
    *((void **) (context->Rsp + 0)) = NULL;
    context->Rip = (DWORD64) gum_script_memory_do_longjmp;
#endif

    return TRUE;
  }

  return FALSE;
}

#else

static void
gum_script_memory_on_invalid_access (int sig,
                                     siginfo_t * siginfo,
                                     void * context)
{
  GumMemoryAccessScope * scope;
  struct sigaction * action;

  scope = (GumMemoryAccessScope *)
      GUM_TLS_KEY_GET_VALUE (gum_memaccess_scope_tls);
  if (scope == NULL)
    goto not_our_fault;

  if (!scope->exception_occurred)
  {
    scope->exception_occurred = TRUE;

    scope->address = siginfo->si_addr;
    GUM_LONGJMP (scope->env, 1);
  }

not_our_fault:
  action =
      (sig == SIGSEGV) ? &gum_memaccess_old_sigsegv : &gum_memaccess_old_sigbus;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (action->sa_sigaction != NULL)
      action->sa_sigaction (sig, siginfo, context);
    else
      abort ();
  }
  else
  {
    if (action->sa_handler != NULL)
      action->sa_handler (sig);
    else
      abort ();
  }
}

#endif

static void
gum_script_memory_on_scan (const FunctionCallbackInfo<Value> & info)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      info.Data ().As<External> ()->Value ());
  GumScriptCore * core = self->core;
  Isolate * isolate = core->isolate;

  gpointer address;
  if (!_gum_script_pointer_get (info[0], &address, core))
    return;
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = info[1]->IntegerValue ();

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
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &on_match, core))
    return;
  Local<Function> on_error;
  if (!_gum_script_callbacks_get_opt (callbacks, "onError", &on_error, core))
    return;
  Local<Function> on_complete;
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &on_complete, core))
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
    ctx->receiver = new GumPersistent<Value>::type (isolate, info.This ());

    _gum_script_core_push_job (self->core, gum_script_do_memory_scan, ctx,
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
  if (ctx == NULL)
    return;

  gum_match_pattern_free (ctx->pattern);

  {
    ScriptScope script_scope (ctx->core->script);
    delete ctx->on_match;
    delete ctx->on_error;
    delete ctx->on_complete;
    delete ctx->receiver;
  }

  g_slice_free (GumMemoryScanContext, ctx);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_script_do_memory_scan (gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    gum_memory_scan (&ctx->range, ctx->pattern, gum_script_process_scan_match,
        ctx);
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  {
    ScriptScope script_scope (ctx->core->script);
    Isolate * isolate = ctx->core->isolate;

    Local<Value> receiver (Local<Value>::New (isolate,
        *ctx->receiver));

    if (scope.exception_occurred && ctx->on_error != NULL)
    {
      gchar * message = g_strdup_printf (
          "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (scope.address));
      Local<Function> on_error (Local<Function>::New (isolate,
          *ctx->on_error));
      Handle<Value> argv[] = { String::NewFromUtf8 (isolate, message) };
      on_error->Call (receiver, 1, argv);
      g_free (message);
    }

    Local<Function> on_complete (Local<Function>::New (isolate,
        *ctx->on_complete));
    on_complete->Call (receiver, 0, 0);
  }
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

static gboolean
gum_script_process_scan_match (GumAddress address,
                               gsize size,
                               gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  ScriptScope scope (ctx->core->script);
  Isolate * isolate = ctx->core->isolate;

  Local<Function> on_match (Local<Function>::New (isolate, *ctx->on_match));
  Local<Value> receiver (Local<Value>::New (isolate, *ctx->receiver));
  Handle<Value> argv[] = {
    _gum_script_pointer_new (GSIZE_TO_POINTER (address), ctx->core),
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
