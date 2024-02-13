/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickmemory.h"

#include "gumquickmacros.h"

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
  JSValue apply;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  JSValue on_match;
  JSValue on_error;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumMemoryScanSyncContext
{
  JSValue matches;
  uint32_t index;

  JSContext * ctx;
  GumQuickCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)
GUMJS_DECLARE_FUNCTION (gumjs_memory_query_protection)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_check_code_pointer)

static JSValue gum_quick_memory_read (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);
static JSValue gum_quick_memory_write (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);
GUMJS_DECLARE_FUNCTION (gum_quick_memory_read_volatile)

static void gum_quick_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumQuickMemory * self);

#ifdef HAVE_WINDOWS
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUMJS_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
    { \
      return gum_quick_memory_read (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
    { \
      return gum_quick_memory_write (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
    GUMJS_DEFINE_MEMORY_READ (T); \
    GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    JS_CFUNC_DEF ("read" N, 0, gumjs_memory_read_##T)
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    JS_CFUNC_DEF ("write" N, 0, gumjs_memory_write_##T)
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
    GumMemoryScanSyncContext * sc);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)
static void gum_quick_memory_clear_monitor (GumQuickMemory * self,
    JSContext * ctx);

GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_operation)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_from)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_address)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_range_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_page_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_completed)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_total)

static const JSCFunctionListEntry gumjs_memory_entries[] =
{
  JS_CFUNC_DEF ("_alloc", 0, gumjs_memory_alloc),
  JS_CFUNC_DEF ("copy", 0, gumjs_memory_copy),
  JS_CFUNC_DEF ("protect", 0, gumjs_memory_protect),
  JS_CFUNC_DEF ("queryProtection", 0, gumjs_memory_query_protection),
  JS_CFUNC_DEF ("_patchCode", 0, gumjs_memory_patch_code),
  JS_CFUNC_DEF ("_checkCodePointer", 0, gumjs_memory_check_code_pointer),

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
  JS_CFUNC_DEF ("readVolatile", 0, gum_quick_memory_read_volatile),

  JS_CFUNC_DEF ("allocAnsiString", 0, gumjs_memory_alloc_ansi_string),
  JS_CFUNC_DEF ("allocUtf8String", 0, gumjs_memory_alloc_utf8_string),
  JS_CFUNC_DEF ("allocUtf16String", 0, gumjs_memory_alloc_utf16_string),

  JS_CFUNC_DEF ("_scan", 0, gumjs_memory_scan),
  JS_CFUNC_DEF ("scanSync", 0, gumjs_memory_scan_sync),
};

static const JSCFunctionListEntry gumjs_memory_access_monitor_entries[] =
{
  JS_CFUNC_DEF ("enable", 0, gumjs_memory_access_monitor_enable),
  JS_CFUNC_DEF ("disable", 0, gumjs_memory_access_monitor_disable),
};

static const JSClassDef gumjs_memory_access_details_def =
{
  .class_name = "MemoryAccessDetails",
};

static const JSCFunctionListEntry gumjs_memory_access_details_entries[] =
{
  JS_CGETSET_DEF ("operation", gumjs_memory_access_details_get_operation, NULL),
  JS_CGETSET_DEF ("from", gumjs_memory_access_details_get_from, NULL),
  JS_CGETSET_DEF ("address", gumjs_memory_access_details_get_address, NULL),
  JS_CGETSET_DEF ("rangeIndex", gumjs_memory_access_details_get_range_index,
      NULL),
  JS_CGETSET_DEF ("pageIndex", gumjs_memory_access_details_get_page_index,
      NULL),
  JS_CGETSET_DEF ("pagesCompleted",
      gumjs_memory_access_details_get_pages_completed, NULL),
  JS_CGETSET_DEF ("pagesTotal", gumjs_memory_access_details_get_pages_total,
      NULL),
};

void
_gum_quick_memory_init (GumQuickMemory * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto;

  self->core = core;
  self->monitor = NULL;
  self->on_access = JS_NULL;

  _gum_quick_core_store_module_data (core, "memory", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_memory_entries,
      G_N_ELEMENTS (gumjs_memory_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Memory", obj, JS_PROP_C_W_E);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_memory_access_monitor_entries,
      G_N_ELEMENTS (gumjs_memory_access_monitor_entries));
  JS_DefinePropertyValueStr (ctx, ns, "MemoryAccessMonitor", obj,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_memory_access_details_def, core,
      &self->memory_access_details_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_memory_access_details_entries,
      G_N_ELEMENTS (gumjs_memory_access_details_entries));
}

void
_gum_quick_memory_dispose (GumQuickMemory * self)
{
  gum_quick_memory_clear_monitor (self, self->core->ctx);
}

void
_gum_quick_memory_finalize (GumQuickMemory * self)
{
}

static GumQuickMemory *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "memory");
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  gsize size, page_size;
  GumAddressSpec spec;

  if (!_gum_quick_args_parse (args, "ZpZ", &size, &spec.near_address,
      &spec.max_distance))
    return JS_EXCEPTION;

  if (size == 0 || size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  page_size = gum_query_page_size ();

  if (spec.near_address != NULL)
  {
    gpointer result;

    if ((size % page_size) != 0)
    {
      return _gum_quick_throw_literal (ctx,
          "size must be a multiple of page size");
    }

    result = gum_try_alloc_n_pages_near (size / page_size, GUM_PAGE_RW, &spec);
    if (result == NULL)
    {
      return _gum_quick_throw_literal (ctx,
          "unable to allocate free page(s) near address");
    }

    return _gum_quick_native_resource_new (ctx, result, gum_free_pages, core);
  }
  else
  {
    if ((size % page_size) != 0)
    {
      return _gum_quick_native_resource_new (ctx, g_malloc0 (size), g_free,
          core);
    }
    else
    {
      return _gum_quick_native_resource_new (ctx,
          gum_alloc_n_pages (size / page_size, GUM_PAGE_RW), gum_free_pages,
          core);
    }
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  GumExceptor * exceptor = core->exceptor;
  gpointer destination, source;
  gsize size;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "ppZ", &destination, &source, &size))
    return JS_EXCEPTION;

  if (size == 0)
    return JS_UNDEFINED;
  else if (size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  if (gum_exceptor_try (exceptor, &scope))
  {
    memmove (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    return _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  gsize size;
  GumPageProtection prot;
  gboolean success;

  if (!_gum_quick_args_parse (args, "pZm", &address, &size, &prot))
    return JS_EXCEPTION;

  if (size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  if (size != 0)
    success = gum_try_mprotect (address, size, prot);
  else
    success = TRUE;

  return JS_NewBool (ctx, success);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_query_protection)
{
  gpointer address;
  GumPageProtection prot;

  if (!_gum_quick_args_parse (args, "p", &address))
    goto propagate_exception;

  if (!gum_memory_query_protection (address, &prot))
    goto query_failed;

  return _gum_quick_page_protection_new (ctx, prot);

query_failed:
  _gum_quick_throw_literal (ctx, "failed to query address");

propagate_exception:
  return JS_EXCEPTION;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_patch_code)
{
  gpointer address;
  gsize size;
  GumMemoryPatchContext pc;
  gboolean success;

  if (!_gum_quick_args_parse (args, "pZF", &address, &size, &pc.apply))
    return JS_EXCEPTION;
  pc.ctx = ctx;
  pc.core = core;

  success = gum_memory_patch_code (address, size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success)
    return _gum_quick_throw_literal (ctx, "invalid address");

  return JS_UNDEFINED;
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  JSValue mem_val;

  mem_val = _gum_quick_native_pointer_new (ctx, mem, core);

  _gum_quick_scope_call_void (self->core->current_scope, self->apply,
      JS_UNDEFINED, 1, &mem_val);

  JS_FreeValue (ctx, mem_val);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_check_code_pointer)
{
  JSValue result = JS_NULL;
  const guint8 * ptr;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "p", &ptr))
    return JS_EXCEPTION;

  ptr = gum_strip_code_pointer ((gpointer) ptr);

#ifdef HAVE_ARM
  ptr = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~1);
#endif

  gum_ensure_code_readable (ptr, 1);

  if (gum_exceptor_try (exceptor, &scope))
  {
    result = JS_NewUint32 (ctx, *ptr);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    return _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static JSValue
gum_quick_memory_read (JSContext * ctx,
                       GumMemoryValueType type,
                       GumQuickArgs * args,
                       GumQuickCore * core)
{
  JSValue result = JS_NULL;
  GumExceptor * exceptor = core->exceptor;
  gpointer address;
  gssize length = -1;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_quick_args_parse (args, "pZ", &address, &length))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_quick_args_parse (args, "p|z", &address, &length))
        return JS_EXCEPTION;
      break;
    default:
      if (!_gum_quick_args_parse (args, "p", &address))
        return JS_EXCEPTION;
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result =
            _gum_quick_native_pointer_new (ctx, *((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = JS_NewInt32 (ctx, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = JS_NewUint32 (ctx, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = JS_NewInt32 (ctx, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = JS_NewUint32 (ctx, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = JS_NewInt32 (ctx, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = JS_NewUint32 (ctx, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_quick_int64_new (ctx, *((gint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_quick_uint64_new (ctx, *((guint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_quick_int64_new (ctx, *((glong *) address), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_quick_uint64_new (ctx, *((gulong *) address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = JS_NewFloat64 (ctx, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = JS_NewFloat64 (ctx, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = address;
        gpointer buffer_data;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        buffer_data = g_malloc (length);
        result = JS_NewArrayBuffer (ctx, buffer_data, length,
            _gum_quick_array_buffer_free, buffer_data, FALSE);

        memcpy (buffer_data, data, length);

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        const gchar * data = address;
        guint8 dummy_to_trap_bad_pointer_early;
        gchar * str;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        str = g_utf8_make_valid (data, length);
        result = JS_NewString (ctx, str);
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const gchar * data = address;
        guint8 dummy_to_trap_bad_pointer_early;
        const gchar * end;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        if (g_utf8_validate (data, length, &end))
        {
          result = JS_NewStringLen (ctx, data, end - data);
        }
        else
        {
          result = _gum_quick_throw (ctx,
              "can't decode byte 0x%02x in position %u",
              (guint8) *end, (guint) (end - data));
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        const gunichar2 * str_utf16 = address;
        gchar * str_utf8;
        guint8 dummy_to_trap_bad_pointer_early;
        glong size;

        if (str_utf16 == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, sizeof (guint8));

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);

        if (str_utf8 != NULL)
          result = JS_NewString (ctx, str_utf8);
        else
          result = _gum_quick_throw_literal (ctx, "invalid string");

        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        const gchar * str_ansi = address;

        if (str_ansi == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          gchar * str_utf8;

          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          result = JS_NewString (ctx, str_utf8);
          g_free (str_utf8);
        }
        else
        {
          result = JS_NewString (ctx, "");
        }
#else
        result = _gum_quick_throw_literal (ctx,
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
    JS_FreeValue (ctx, result);
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static JSValue
gum_quick_memory_write (JSContext * ctx,
                        GumMemoryValueType type,
                        GumQuickArgs * args,
                        GumQuickCore * core)
{
  JSValue result = JS_UNDEFINED;
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
      if (!_gum_quick_args_parse (args, "pp", &address, &pointer))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_quick_args_parse (args, "pz", &address, &s))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_quick_args_parse (args, "pZ", &address, &u))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_quick_args_parse (args, "pq", &address, &s64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_quick_args_parse (args, "pQ", &address, &u64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_quick_args_parse (args, "pn", &address, &number))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_quick_args_parse (args, "pB", &address, &bytes))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_quick_args_parse (args, "ps", &address, &str))
        return JS_EXCEPTION;

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
        result = _gum_quick_throw_literal (ctx,
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
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  g_free (str_utf16);
#ifdef HAVE_WINDOWS
  g_free (str_ansi);
#endif

  return result;
}

GUMJS_DEFINE_FUNCTION (gum_quick_memory_read_volatile)
{
  gpointer address;
  gsize length;
  gsize n_bytes_read;
  guint8 * data;

  if (!_gum_quick_args_parse (args, "pz", &address, &length))
    return JS_EXCEPTION;

  if (length == 0)
    return JS_NULL;

  data = gum_memory_read (address, length, &n_bytes_read);
  if (data == NULL)
    return _gum_quick_throw_literal (ctx, "memory read failed");

  return JS_NewArrayBuffer (ctx, data, n_bytes_read,
      _gum_quick_array_buffer_free, data, FALSE);
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

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  str_ansi = gum_ansi_string_from_utf8 (str);

  return _gum_quick_native_resource_new (ctx, str_ansi, g_free, core);
#else
  return _gum_quick_throw_literal (ctx,
      "ANSI API is only applicable on Windows");
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  const gchar * str;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  return _gum_quick_native_resource_new (ctx, g_strdup (str), g_free, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  const gchar * str;
  gunichar2 * str_utf16;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

  return _gum_quick_native_resource_new (ctx, str_utf16, g_free, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  gpointer address;
  gsize size;
  GumMemoryScanContext sc;

  if (!_gum_quick_args_parse (args, "pZMF{onMatch,onError,onComplete}",
      &address, &size, &sc.pattern, &sc.on_match, &sc.on_error,
      &sc.on_complete))
    return JS_EXCEPTION;

  sc.range.base_address = GUM_ADDRESS (address);
  sc.range.size = size;

  gum_match_pattern_ref (sc.pattern);

  JS_DupValue (ctx, sc.on_match);
  JS_DupValue (ctx, sc.on_error);
  JS_DupValue (ctx, sc.on_complete);

  sc.result = GUM_QUICK_MATCH_CONTINUE;

  sc.ctx = ctx;
  sc.core = core;

  _gum_quick_core_pin (core);
  _gum_quick_core_push_job (core,
      (GumScriptJobFunc) gum_memory_scan_context_run,
      g_slice_dup (GumMemoryScanContext, &sc),
      (GDestroyNotify) gum_memory_scan_context_free);

  return JS_UNDEFINED;
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_match);
  JS_FreeValue (ctx, self->on_error);
  JS_FreeValue (ctx, self->on_complete);

  _gum_quick_core_unpin (core);
  _gum_quick_scope_leave (&scope);

  gum_match_pattern_unref (self->pattern);

  g_slice_free (GumMemoryScanContext, self);
}

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope exceptor_scope;
  GumQuickScope script_scope;

  if (gum_exceptor_try (exceptor, &exceptor_scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_memory_scan_context_emit_match, self);
  }

  _gum_quick_scope_enter (&script_scope, core);

  if (gum_exceptor_catch (exceptor, &exceptor_scope))
  {
    if (!JS_IsNull (self->on_error))
    {
      gchar * message;
      JSValue message_val;

      message = gum_exception_details_to_string (&exceptor_scope.exception);
      message_val = JS_NewString (ctx, message);
      g_free (message);

      _gum_quick_scope_call_void (&script_scope, self->on_error, JS_UNDEFINED,
          1, &message_val);
    }
  }

  if (self->result != GUM_QUICK_MATCH_ERROR)
  {
    _gum_quick_scope_call_void (&script_scope, self->on_complete, JS_UNDEFINED,
        0, NULL);
  }

  _gum_quick_scope_leave (&script_scope);
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  gboolean proceed;
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;
  JSValue argv[2];
  JSValue result;

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address),
      core);
  argv[1] = JS_NewUint32 (ctx, size);

  result = _gum_quick_scope_call (&scope, self->on_match, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  proceed = _gum_quick_process_match_result (ctx, &result, &self->result);

  _gum_quick_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  JSValue result;
  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  GumMemoryRange range;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "pZM", &address, &size, &pattern))
    return JS_EXCEPTION;

  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  result = JS_NewArray (ctx);

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    GumMemoryScanSyncContext sc;

    sc.matches = result;
    sc.index = 0;

    sc.ctx = ctx;
    sc.core = core;

    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        &sc);
  }

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    JS_FreeValue (ctx, result);
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumMemoryScanSyncContext * sc)
{
  JSContext * ctx = sc->ctx;
  GumQuickCore * core = sc->core;
  JSValue m;

  m = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, size),
      JS_NewUint32 (ctx, size),
      JS_PROP_C_W_E);

  JS_DefinePropertyValueUint32 (ctx, sc->matches, sc->index, m, JS_PROP_C_W_E);
  sc->index++;

  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
  GumQuickMemory * self;
  GArray * ranges;
  JSValue on_access;
  GError * error;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "RF{onAccess}", &ranges, &on_access))
    return JS_EXCEPTION;

  if (ranges->len == 0)
    return _gum_quick_throw_literal (ctx, "expected one or more ranges");

  gum_quick_memory_clear_monitor (self, ctx);

  self->on_access = JS_DupValue (ctx, on_access);
  self->monitor = gum_memory_access_monitor_new (
      (GumMemoryRange *) ranges->data, ranges->len, GUM_PAGE_RWX, TRUE,
      (GumMemoryAccessNotify) gum_quick_memory_on_access, self, NULL);

  if (!gum_memory_access_monitor_enable (self->monitor, &error))
  {
    _gum_quick_throw_error (ctx, &error);

    gum_quick_memory_clear_monitor (self, ctx);

    return JS_EXCEPTION;
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
  GumQuickMemory * self = gumjs_get_parent_module (core);

  gum_quick_memory_clear_monitor (self, ctx);

  return JS_UNDEFINED;
}

static void
gum_quick_memory_clear_monitor (GumQuickMemory * self,
                                JSContext * ctx)
{
  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  if (!JS_IsNull (self->on_access))
  {
    JS_FreeValue (ctx, self->on_access);
    self->on_access = JS_NULL;
  }
}

static void
gum_quick_memory_on_access (GumMemoryAccessMonitor * monitor,
                            const GumMemoryAccessDetails * details,
                            GumQuickMemory * self)
{
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;
  GumQuickScope scope;
  JSValue d;

  _gum_quick_scope_enter (&scope, core);

  d = JS_NewObjectClass (ctx, self->memory_access_details_class);
  JS_SetOpaque (d, (void *) details);

  _gum_quick_scope_call_void (&scope, self->on_access, JS_UNDEFINED, 1, &d);

  JS_SetOpaque (d, NULL);
  JS_FreeValue (ctx, d);

  _gum_quick_scope_leave (&scope);
}

static gboolean
gum_quick_memory_access_details_get (JSContext * ctx,
                                     JSValueConst val,
                                     GumQuickCore * core,
                                     const GumMemoryAccessDetails ** details)
{
  const GumMemoryAccessDetails * d;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->memory_access_details_class, core,
      (gpointer *) &d))
    return FALSE;

  if (d == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *details = d;
  return TRUE;
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_operation)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return _gum_quick_memory_operation_new (ctx, details->operation);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_from)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, details->from, core);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_address)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, details->address, core);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_range_index)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, details->range_index);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_page_index)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, details->page_index);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_pages_completed)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, details->pages_completed);
}

GUMJS_DEFINE_GETTER (gumjs_memory_access_details_get_pages_total)
{
  const GumMemoryAccessDetails * details;

  if (!gum_quick_memory_access_details_get (ctx, this_val, core, &details))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, details->pages_total);
}
