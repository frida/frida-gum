/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscriptmemory.h"

#include "gumscriptscope.h"
#include "gumtls.h"
#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#endif

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
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct _GumMemoryScanContext
{
  GumScriptCore * core;
  GumMemoryRange range;
  GumMatchPattern * pattern;
  Persistent<Function> on_match;
  Persistent<Function> on_error;
  Persistent<Function> on_complete;
  Persistent<Object> receiver;
};

static Handle<Value> gum_script_memory_on_alloc (const Arguments & args);
static void gum_script_on_free_malloc_pointer (Persistent<Value> object,
    void * data);
static Handle<Value> gum_script_memory_on_read_pointer (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_write_pointer (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_read_s8 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_u8 (const Arguments & args);
static Handle<Value> gum_script_memory_on_write_u8 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_s16 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_u16 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_s32 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_u32 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_s64 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_u64 (const Arguments & args);
static Handle<Value> gum_script_memory_on_read_byte_array (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_read_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_write_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_read_utf16_string (
    const Arguments & args);
#ifdef G_OS_WIN32
static Handle<Value> gum_script_memory_on_read_ansi_string (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_alloc_ansi_string (
    const Arguments & args);
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif
static Handle<Value> gum_script_memory_on_alloc_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_memory_on_alloc_utf16_string (
    const Arguments & args);
static Handle<Value> gum_script_memory_do_read (const Arguments & args,
    GumMemoryValueType type);
static Handle<Value> gum_script_memory_do_write (const Arguments & args,
    GumMemoryValueType type);
static void gum_script_array_free (Persistent<Value> object, void * data);

static Handle<Value> gum_script_memory_on_scan (const Arguments & args);
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static gboolean gum_script_do_memory_scan (GIOSchedulerJob * job,
    GCancellable * cancellable, gpointer user_data);
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

void
_gum_script_memory_init (GumScriptMemory * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  self->core = core;

  Handle<ObjectTemplate> memory = ObjectTemplate::New ();
  memory->Set (String::New ("alloc"),
      FunctionTemplate::New (gum_script_memory_on_alloc,
          External::Wrap (self)));
  memory->Set (String::New ("readPointer"),
      FunctionTemplate::New (gum_script_memory_on_read_pointer,
          External::Wrap (self)));
  memory->Set (String::New ("writePointer"),
      FunctionTemplate::New (gum_script_memory_on_write_pointer,
          External::Wrap (self)));
  memory->Set (String::New ("readS8"),
      FunctionTemplate::New (gum_script_memory_on_read_s8,
          External::Wrap (self)));
  memory->Set (String::New ("readU8"),
      FunctionTemplate::New (gum_script_memory_on_read_u8,
          External::Wrap (self)));
  memory->Set (String::New ("writeU8"),
      FunctionTemplate::New (gum_script_memory_on_write_u8,
          External::Wrap (self)));
  memory->Set (String::New ("readS16"),
      FunctionTemplate::New (gum_script_memory_on_read_s16,
          External::Wrap (self)));
  memory->Set (String::New ("readU16"),
      FunctionTemplate::New (gum_script_memory_on_read_u16,
          External::Wrap (self)));
  memory->Set (String::New ("readS32"),
      FunctionTemplate::New (gum_script_memory_on_read_s32,
          External::Wrap (self)));
  memory->Set (String::New ("readU32"),
      FunctionTemplate::New (gum_script_memory_on_read_u32,
          External::Wrap (self)));
  memory->Set (String::New ("readS64"),
      FunctionTemplate::New (gum_script_memory_on_read_s64,
          External::Wrap (self)));
  memory->Set (String::New ("readU64"),
      FunctionTemplate::New (gum_script_memory_on_read_u64,
          External::Wrap (self)));
  memory->Set (String::New ("readByteArray"),
      FunctionTemplate::New (gum_script_memory_on_read_byte_array,
          External::Wrap (self)));
  memory->Set (String::New ("readUtf8String"),
      FunctionTemplate::New (gum_script_memory_on_read_utf8_string,
          External::Wrap (self)));
  memory->Set (String::New ("writeUtf8String"),
      FunctionTemplate::New (gum_script_memory_on_write_utf8_string,
          External::Wrap (self)));
  memory->Set (String::New ("readUtf16String"),
      FunctionTemplate::New (gum_script_memory_on_read_utf16_string,
          External::Wrap (self)));
#ifdef G_OS_WIN32
  memory->Set (String::New ("readAnsiString"),
      FunctionTemplate::New (gum_script_memory_on_read_ansi_string,
          External::Wrap (self)));
  memory->Set (String::New ("allocAnsiString"),
      FunctionTemplate::New (gum_script_memory_on_alloc_ansi_string,
          External::Wrap (self)));
#endif
  memory->Set (String::New ("allocUtf8String"),
      FunctionTemplate::New (gum_script_memory_on_alloc_utf8_string,
          External::Wrap (self)));
  memory->Set (String::New ("allocUtf16String"),
      FunctionTemplate::New (gum_script_memory_on_alloc_utf16_string,
          External::Wrap (self)));
  memory->Set (String::New ("scan"),
      FunctionTemplate::New (gum_script_memory_on_scan,
          External::Wrap (self)));
  scope->Set (String::New ("Memory"), memory);

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
}

void
_gum_script_memory_dispose (GumScriptMemory * self)
{
}

void
_gum_script_memory_finalize (GumScriptMemory * self)
{
#ifdef G_OS_WIN32
  gum_win_exception_hook_remove (gum_script_memory_on_exception);
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

static Handle<Value>
gum_script_memory_on_alloc (const Arguments & args)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));

  uint32_t size = args[0]->Uint32Value ();
  if (size > 0x7fffffff)
  {
    ThrowException (Exception::TypeError (String::New ("invalid size")));
    return Undefined ();
  }

  gpointer block = g_malloc (size);
  Handle<Object> instance = _gum_script_pointer_new (self->core, block);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (block, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static void
gum_script_on_free_malloc_pointer (Persistent<Value> object,
                                   void * data)
{
  HandleScope handle_scope;
  g_free (data);
  object.Dispose ();
}

static Handle<Value>
gum_script_memory_on_read_pointer (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_POINTER);
}

static Handle<Value>
gum_script_memory_on_write_pointer (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_POINTER);
}

static Handle<Value>
gum_script_memory_on_read_s8 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S8);
}

static Handle<Value>
gum_script_memory_on_read_u8 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U8);
}

static Handle<Value>
gum_script_memory_on_write_u8 (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_U8);
}

static Handle<Value>
gum_script_memory_on_read_s16 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S16);
}

static Handle<Value>
gum_script_memory_on_read_u16 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U16);
}

static Handle<Value>
gum_script_memory_on_read_s32 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S32);
}

static Handle<Value>
gum_script_memory_on_read_u32 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U32);
}

static Handle<Value>
gum_script_memory_on_read_s64 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S64);
}

static Handle<Value>
gum_script_memory_on_read_u64 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U64);
}

static Handle<Value>
gum_script_memory_on_read_byte_array (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_BYTE_ARRAY);
}

static Handle<Value>
gum_script_memory_on_read_utf8_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_UTF8_STRING);
}

static Handle<Value>
gum_script_memory_on_write_utf8_string (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_UTF8_STRING);
}

static Handle<Value>
gum_script_memory_on_read_utf16_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_UTF16_STRING);
}

#ifdef G_OS_WIN32

static Handle<Value>
gum_script_memory_on_read_ansi_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_ANSI_STRING);
}

static Handle<Value>
gum_script_memory_on_alloc_ansi_string (const Arguments & args)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gchar * str_heap = gum_ansi_string_from_utf8 (*str);
  Handle<Object> instance = _gum_script_pointer_new (self->core, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
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

static Handle<Value>
gum_script_memory_on_alloc_utf8_string (const Arguments & args)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gchar * str_heap = g_strdup (*str);
  Handle<Object> instance = _gum_script_pointer_new (self->core, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static Handle<Value>
gum_script_memory_on_alloc_utf16_string (const Arguments & args)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gunichar2 * str_heap = g_utf8_to_utf16 (*str, -1, NULL, NULL, NULL);
  Handle<Object> instance = _gum_script_pointer_new (self->core, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static Handle<Value>
gum_script_memory_do_read (const Arguments & args,
                           GumMemoryValueType type)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;
  Handle<Value> result;

  gpointer address;
  if (!_gum_script_pointer_get (self->core, args[0], &address))
    return Undefined ();

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_script_pointer_new (self->core,
            *static_cast<const gpointer *> (address));
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (*static_cast<const gint8 *> (address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (*static_cast<const guint8 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (*static_cast<const gint16 *> (address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (*static_cast<const guint16 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (*static_cast<const gint32 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (*static_cast<const guint32 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = Number::New (*static_cast<const gint64 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = Number::New (*static_cast<const guint64 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = static_cast<const guint8 *> (address);
        if (data == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = args[1]->IntegerValue ();
        Handle<Object> array;
        if (length > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          guint8 * buffer;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          buffer = static_cast<guint8 *> (g_memdup (data, length));
          V8::AdjustAmountOfExternalAllocatedMemory (length);

          array = Object::New ();
          array->Set (String::New ("length"), Int32::New (length), ReadOnly);
          array->SetIndexedPropertiesToExternalArrayData (buffer,
              kExternalUnsignedByteArray, length);
          Persistent<Object> persistent_array = Persistent<Object>::New (array);
          persistent_array.MakeWeak (buffer, gum_script_array_free);
          persistent_array.MarkIndependent ();
        }
        else
        {
          array = Object::New ();
          length = 0;
        }
        array->Set (String::New ("length"), Int32::New (length), ReadOnly);

        result = array;
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const char * data = static_cast<const char *> (address);
        if (data == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = -1;
        if (args.Length () > 1)
          length = args[1]->IntegerValue();
        if (length < 0)
          length = g_utf8_strlen (data, -1);

        if (length != 0)
        {
          int size = g_utf8_offset_to_pointer (data, length) - data;
          result = String::New (data, size);
        }
        else
        {
          result = String::Empty ();
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
          result = Null ();
          break;
        }

        memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        length = (args.Length () > 1) ? args[1]->IntegerValue() : -1;
        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);

        length = size / sizeof (gunichar2);
        if (length != 0)
          result = String::New (str_utf8, size);
        else
          result = String::Empty ();

        break;
      }
#ifdef G_OS_WIN32
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
        const char * str_ansi = static_cast<const char *> (address);
        if (str_ansi == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = -1;
        if (args.Length () > 1)
          length = args[1]->IntegerValue();

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          gchar * str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          int size = g_utf8_offset_to_pointer (str_utf8,
              g_utf8_strlen (str_utf8, -1)) - str_utf8;
          result = String::New (str_utf8, size);
          g_free (str_utf8);
        }
        else
        {
          result = String::Empty ();
        }

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
        "access violation reading 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    ThrowException (Exception::Error (String::New (message)));
    g_free (message);

    result = Undefined ();
  }

  return result;
}

static Handle<Value>
gum_script_memory_do_write (const Arguments & args,
                            GumMemoryValueType type)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  gpointer address;
  if (!_gum_script_pointer_get (self->core, args[0], &address))
    return Undefined ();

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
      {
        gpointer value;
        if (_gum_script_pointer_get (self->core, args[1], &value))
          *static_cast<gpointer *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U8:
      {
        guint8 value = args[1]->Uint32Value ();
        *static_cast<guint8 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        String::Utf8Value str (args[1]);
        strcpy (static_cast<char *> (address), *str);
        break;
      }
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
    ThrowException (Exception::Error (String::New (message)));
    g_free (message);
  }

  return Undefined ();
}

static void
gum_script_array_free (Persistent<Value> object,
                       void * data)
{
  int32_t length;

  HandleScope handle_scope;
  length = object->ToObject ()->Get (String::New ("length"))->Uint32Value ();
  V8::AdjustAmountOfExternalAllocatedMemory (-length);
  g_free (data);
  object.Dispose ();
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

static Handle<Value>
gum_script_memory_on_scan (const Arguments & args)
{
  GumScriptMemory * self = static_cast<GumScriptMemory *> (
      External::Unwrap (args.Data ()));

  gpointer address;
  if (!_gum_script_pointer_get (self->core, args[0], &address))
    return Undefined ();
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = args[1]->IntegerValue ();

  String::Utf8Value match_str (args[2]);

  Local<Value> callbacks_value = args[3];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New ("Memory.scan: "
        "fourth argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  Local<Function> on_match;
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &on_match))
    return Undefined ();
  Local<Function> on_error;
  if (!_gum_script_callbacks_get_opt (callbacks, "onError", &on_error))
    return Undefined ();
  Local<Function> on_complete;
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &on_complete))
    return Undefined ();

  GumMatchPattern * pattern = gum_match_pattern_new_from_string (*match_str);
  if (pattern != NULL)
  {
    GumMemoryScanContext * ctx = g_slice_new (GumMemoryScanContext);

    ctx->core = self->core;
    g_object_ref (ctx->core->script);
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = Persistent<Function>::New (on_match);
    ctx->on_error = Persistent<Function>::New (on_error);
    ctx->on_complete = Persistent<Function>::New (on_complete);
    ctx->receiver = Persistent<Object>::New (args.This ());

    g_io_scheduler_push_job (gum_script_do_memory_scan, ctx,
        reinterpret_cast<GDestroyNotify> (gum_memory_scan_context_free),
        G_PRIORITY_DEFAULT, NULL);
  }
  else
  {
    ThrowException (Exception::Error (String::New ("invalid match pattern")));
  }

  return Undefined ();
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * ctx)
{
  if (ctx == NULL)
    return;

  gum_match_pattern_free (ctx->pattern);

  {
    ScriptScope script_scope (ctx->core->script);
    ctx->on_match.Dispose ();
    ctx->on_error.Dispose ();
    ctx->on_complete.Dispose ();
    ctx->receiver.Dispose ();
  }

  g_object_unref (ctx->core->script);

  g_slice_free (GumMemoryScanContext, ctx);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static gboolean
gum_script_do_memory_scan (GIOSchedulerJob * job,
                           GCancellable * cancellable,
                           gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  (void) job;
  (void) cancellable;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    gum_memory_scan (&ctx->range, ctx->pattern, gum_script_process_scan_match,
        ctx);
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  {
    ScriptScope script_scope (ctx->core->script);

    if (scope.exception_occurred && !ctx->on_error.IsEmpty ())
    {
      gchar * message = g_strdup_printf (
          "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (scope.address));
      Handle<Value> argv[] = { String::New (message) };
      ctx->on_error->Call (ctx->receiver, 1, argv);
      g_free (message);
    }

    ctx->on_complete->Call (ctx->receiver, 0, 0);
  }

  return FALSE;
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

  Handle<Value> argv[] = {
    _gum_script_pointer_new (ctx->core, GSIZE_TO_POINTER (address)),
    Integer::NewFromUnsigned (size)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 2, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

