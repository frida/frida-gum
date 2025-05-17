/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2025 Kenjiro Ichise <ichise@doranekosystems.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8memory.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <wchar.h>
#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

#define GUMJS_MODULE_NAME Memory

using namespace v8;

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
  Global<Function> * on_match;
  Global<Function> * on_error;
  Global<Function> * on_complete;

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
GUMJS_DECLARE_FUNCTION (gumjs_memory_query_protection)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_check_code_pointer)

#ifdef HAVE_WINDOWS
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

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
static void gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumV8Memory * self);

static const GumV8Function gumjs_memory_functions[] =
{
  { "_alloc", gumjs_memory_alloc },
  { "copy", gumjs_memory_copy },
  { "protect", gumjs_memory_protect },
  { "queryProtection", gumjs_memory_query_protection },
  { "_patchCode", gumjs_memory_patch_code },
  { "_checkCodePointer", gumjs_memory_check_code_pointer },
  { "allocAnsiString", gumjs_memory_alloc_ansi_string },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string },
  { "_scan", gumjs_memory_scan },
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
                     Local<ObjectTemplate> scope)
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
}

void
_gum_v8_memory_dispose (GumV8Memory * self)
{
  gum_v8_memory_clear_monitor (self);
}

void
_gum_v8_memory_finalize (GumV8Memory * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  gsize size;
  GumAddressSpec spec;
  if (!_gum_v8_args_parse (args, "ZpZ", &size, &spec.near_address,
      &spec.max_distance))
    return;

  if (size == 0 || size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  GumV8NativeResource * res;

  gsize page_size = gum_query_page_size ();

  if (spec.near_address != NULL)
  {
    gpointer result;

    if ((size % page_size) != 0)
    {
      return _gum_v8_throw_ascii_literal (isolate,
          "size must be a multiple of page size");
    }

    result = gum_try_alloc_n_pages_near (size / page_size, GUM_PAGE_RW, &spec);
    if (result == NULL)
    {
      return _gum_v8_throw_ascii_literal (isolate,
          "unable to allocate free page(s) near address");
    }

    res = _gum_v8_native_resource_new (result, size, gum_free_pages, core);
  }
  else
  {
    if ((size % page_size) != 0)
    {
      res = _gum_v8_native_resource_new (g_malloc0 (size), size, g_free, core);
    }
    else
    {
      res = _gum_v8_native_resource_new (
          gum_alloc_n_pages (size / page_size, GUM_PAGE_RW), size,
          gum_free_pages, core);
    }
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

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
    memmove (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
}

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

GUMJS_DEFINE_FUNCTION (gumjs_memory_query_protection)
{
  gpointer address;
  GumPageProtection prot;

  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  if (!gum_memory_query_protection (address, &prot))
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to query address");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_page_protection_new (isolate,  prot));
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

  success = gum_memory_patch_code (address, size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success && !pc.has_pending_exception)
    _gum_v8_throw_ascii_literal (isolate, "invalid address");
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto recv = Undefined (isolate);
  Local<Value> argv[] = { _gum_v8_native_pointer_new (mem, self->core) };
  auto result = self->apply->Call (context, recv, G_N_ELEMENTS (argv), argv);
  self->has_pending_exception = result.IsEmpty ();
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_check_code_pointer)
{
  const guint8 * ptr;
  auto exceptor = core->exceptor;
  GumExceptorScope scope;

  if (!_gum_v8_args_parse (args, "p", &ptr))
    return;

  ptr = (const guint8 *) gum_strip_code_pointer ((gpointer) ptr);

#ifdef HAVE_ARM
  ptr = (const guint8 *) GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~1);
#endif

  gum_ensure_code_readable (ptr, 1);

  if (gum_exceptor_try (exceptor, &scope))
  {
    info.GetReturnValue ().Set (Integer::NewFromUnsigned (isolate, *ptr));
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

#ifdef HAVE_WINDOWS

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  if (length < 0)
    length = (gint) strlen (str_ansi);

  gint str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0,
      str_ansi, length, NULL, 0);
  gsize str_utf16_size = (str_utf16_length + 1) * sizeof (WCHAR);
  WCHAR * str_utf16 = (WCHAR *) g_malloc (str_utf16_size);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      str_utf16, str_utf16_length);
  str_utf16[str_utf16_length] = L'\0';

  gchar * str_utf8 =
      g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);

  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  auto str_utf16 = (WCHAR *)
      g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  gint str_ansi_size = WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      NULL, 0, NULL, NULL);
  auto str_ansi = (gchar *) g_malloc (str_ansi_size);

  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);

  g_free (str_utf16);

  return str_ansi;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef HAVE_WINDOWS
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

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  Local<Function> on_match, on_error, on_complete;
  if (!_gum_v8_args_parse (args, "pZMF{onMatch,onError,onComplete}", &address,
      &size, &pattern, &on_match, &on_error, &on_complete))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  auto ctx = g_slice_new0 (GumMemoryScanContext);
  ctx->range = range;
  ctx->pattern = pattern;
  ctx->on_match = new Global<Function> (isolate, on_match);
  ctx->on_error = new Global<Function> (isolate, on_error);
  ctx->on_complete = new Global<Function> (isolate, on_complete);
  ctx->core = core;

  _gum_v8_core_pin (core);
  _gum_v8_core_push_job (core, (GumScriptJobFunc) gum_memory_scan_context_run,
      ctx, (GDestroyNotify) gum_memory_scan_context_free);
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
{
  auto core = self->core;

  {
    ScriptScope script_scope (core->script);

    delete self->on_match;
    delete self->on_error;
    delete self->on_complete;

    _gum_v8_core_unpin (core);
  }

  gum_match_pattern_unref (self->pattern);

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
    auto context = isolate->GetCurrentContext ();

    auto message = gum_exception_details_to_string (&scope.exception);

    auto on_error = Local<Function>::New (isolate, *self->on_error);
    auto recv = Undefined (isolate);
    Local<Value> argv[] = {
      String::NewFromUtf8 (isolate, message).ToLocalChecked ()
    };
    auto result = on_error->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (result);

    g_free (message);
  }

  {
    ScriptScope script_scope (core->script);
    auto context = isolate->GetCurrentContext ();

    auto on_complete (Local<Function>::New (isolate, *self->on_complete));
    auto recv = Undefined (isolate);
    auto result = on_complete->Call (context, recv, 0, nullptr);
    _gum_v8_ignore_result (result);
  }
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  gboolean proceed = TRUE;

  auto on_match = Local<Function>::New (isolate, *self->on_match);
  auto recv = Undefined (isolate);
  Local<Value> argv[] = {
    _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), self->core),
    Integer::NewFromUnsigned (isolate, size)
  };
  Local<Value> result;
  if (on_match->Call (context, recv, G_N_ELEMENTS (argv), argv)
      .ToLocal (&result) && result->IsString ())
  {
    String::Utf8Value str (isolate, result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  if (info.Length () < 3)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  if (!_gum_v8_args_parse (args, "pZM", &address, &size, &pattern))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  GumMemoryScanSyncContext ctx;
  ctx.matches = Array::New (isolate);
  ctx.core = core;

  GumExceptorScope scope;

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        &ctx);
  }

  gum_match_pattern_unref (pattern);

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

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
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
  module->on_access = new Global<Function> (isolate, on_access);

  GError * error = NULL;
  gum_memory_access_monitor_enable (module->monitor, &error);
  if (_gum_v8_maybe_throw (isolate, &error))
  {
    delete module->on_access;
    module->on_access = nullptr;

    g_object_unref (module->monitor);
    module->monitor = NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
  gum_v8_memory_clear_monitor (module);
}

static void
gum_v8_memory_clear_monitor (GumV8Memory * self)
{
  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  delete self->on_access;
  self->on_access = nullptr;
}

static void
gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
                         const GumMemoryAccessDetails * details,
                         GumV8Memory * self)
{
  auto core = self->core;
  auto isolate = core->isolate;
  ScriptScope script_scope (core->script);

  auto d = Object::New (isolate);
  _gum_v8_object_set (d, "threadId", Number::New (isolate, details->thread_id),
      core);
  _gum_v8_object_set_ascii (d, "operation",
      _gum_v8_memory_operation_to_string (details->operation), core);
  _gum_v8_object_set_pointer (d, "from", details->from, core);
  _gum_v8_object_set_pointer (d, "address", details->address, core);

  _gum_v8_object_set_uint (d, "rangeIndex", details->range_index, core);
  _gum_v8_object_set_uint (d, "pageIndex", details->page_index, core);
  _gum_v8_object_set_uint (d, "pagesCompleted", details->pages_completed, core);
  _gum_v8_object_set_uint (d, "pagesTotal", details->pages_total, core);

  auto context = _gum_v8_cpu_context_new_mutable (details->context, core);
  _gum_v8_object_set (d, "context", context, core);

  auto on_access (Local<Function>::New (isolate, *self->on_access));
  Local<Value> argv[] = { d };
  auto result = on_access->Call (isolate->GetCurrentContext (),
      Undefined (isolate), G_N_ELEMENTS (argv), argv);
  (void) result;

  _gum_v8_cpu_context_free_later (new Global<Object> (isolate, context), core);
}
