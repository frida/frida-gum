/*
 * Copyright (C) 2020-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickprocess.h"

#include "gumquickmacros.h"
#ifdef HAVE_DARWIN
# include <gumdarwin.h>
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ARCH "ia32"
# else
#  define GUM_SCRIPT_ARCH "x64"
# endif
#elif defined (HAVE_ARM)
# define GUM_SCRIPT_ARCH "arm"
#elif defined (HAVE_ARM64)
# define GUM_SCRIPT_ARCH "arm64"
#elif defined (HAVE_MIPS)
# define GUM_SCRIPT_ARCH "mips"
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (HAVE_WINDOWS)
# define GUM_SCRIPT_PLATFORM "windows"
#elif defined (HAVE_FREEBSD)
# define GUM_SCRIPT_PLATFORM "freebsd"
#elif defined (HAVE_QNX)
# define GUM_SCRIPT_PLATFORM "qnx"
#endif

typedef struct _GumQuickMatchContext GumQuickMatchContext;
typedef struct _GumQuickFindModuleByNameContext GumQuickFindModuleByNameContext;
typedef struct _GumQuickFindRangeByAddressContext
    GumQuickFindRangeByAddressContext;

struct _GumQuickExceptionHandler
{
  JSValue callback;
  GumQuickCore * core;
};

struct _GumQuickMatchContext
{
  JSValue on_match;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickProcess * parent;
};

struct _GumQuickFindModuleByNameContext
{
  const gchar * name;
  gboolean name_is_canonical;
  JSValue result;

  JSContext * ctx;
  GumQuickModule * module;
};

struct _GumQuickFindRangeByAddressContext
{
  GumAddress address;
  JSValue result;

  JSContext * ctx;
  GumQuickCore * core;
};

static void gumjs_free_main_module_value (GumQuickProcess * self);
GUMJS_DECLARE_GETTER (gumjs_process_get_main_module)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_home_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_tmp_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
static gboolean gum_store_module_if_name_matches (
    const GumModuleDetails * details, GumQuickFindModuleByNameContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_range_by_address)
static gboolean gum_store_range_if_containing_address (
    const GumRangeDetails * details, GumQuickFindRangeByAddressContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_system_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumQuickExceptionHandler * gum_quick_exception_handler_new (
    JSValue callback, GumQuickCore * core);
static void gum_quick_exception_handler_free (
    GumQuickExceptionHandler * handler);
static gboolean gum_quick_exception_handler_on_exception (
    GumExceptionDetails * details, GumQuickExceptionHandler * handler);

static const JSCFunctionListEntry gumjs_process_entries[] =
{
  JS_PROP_STRING_DEF ("arch", GUM_SCRIPT_ARCH, JS_PROP_C_W_E),
  JS_PROP_STRING_DEF ("platform", GUM_SCRIPT_PLATFORM, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("pointerSize", GLIB_SIZEOF_VOID_P, JS_PROP_C_W_E),
  JS_CGETSET_DEF ("mainModule", gumjs_process_get_main_module, NULL),
  JS_CFUNC_DEF ("getCurrentDir", 0, gumjs_process_get_current_dir),
  JS_CFUNC_DEF ("getHomeDir", 0, gumjs_process_get_home_dir),
  JS_CFUNC_DEF ("getTmpDir", 0, gumjs_process_get_tmp_dir),
  JS_CFUNC_DEF ("isDebuggerAttached", 0, gumjs_process_is_debugger_attached),
  JS_CFUNC_DEF ("getCurrentThreadId", 0, gumjs_process_get_current_thread_id),
  JS_CFUNC_DEF ("_enumerateThreads", 0, gumjs_process_enumerate_threads),
  JS_CFUNC_DEF ("findModuleByName", 0, gumjs_process_find_module_by_name),
  JS_CFUNC_DEF ("_enumerateModules", 0, gumjs_process_enumerate_modules),
  JS_CFUNC_DEF ("findRangeByAddress", 0, gumjs_process_find_range_by_address),
  JS_CFUNC_DEF ("_enumerateRanges", 0, gumjs_process_enumerate_ranges),
  JS_CFUNC_DEF ("enumerateSystemRanges", 0,
      gumjs_process_enumerate_system_ranges),
  JS_CFUNC_DEF ("_enumerateMallocRanges", 0,
      gumjs_process_enumerate_malloc_ranges),
  JS_CFUNC_DEF ("setExceptionHandler", 0, gumjs_process_set_exception_handler),
};

void
_gum_quick_process_init (GumQuickProcess * self,
                         JSValue ns,
                         GumQuickModule * module,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj;

  self->module = module;
  self->core = core;
  self->main_module_value = JS_UNINITIALIZED;

  _gum_quick_core_store_module_data (core, "process", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_process_entries,
      G_N_ELEMENTS (gumjs_process_entries));
  JS_DefinePropertyValueStr (ctx, obj, "id",
      JS_NewInt32 (ctx, gum_process_get_id ()), JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, obj, "pageSize",
      JS_NewInt32 (ctx, gum_query_page_size ()), JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, obj, "codeSigningPolicy",
      JS_NewString (ctx, gum_code_signing_policy_to_string (
          gum_process_get_code_signing_policy ())),
      JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, ns, "Process", obj, JS_PROP_C_W_E);
}

void
_gum_quick_process_flush (GumQuickProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_quick_exception_handler_free);
  gumjs_free_main_module_value (self);
}

void
_gum_quick_process_dispose (GumQuickProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_quick_exception_handler_free);
  gumjs_free_main_module_value (self);
}

static void
gumjs_free_main_module_value (GumQuickProcess * self)
{
  if (JS_IsUninitialized (self->main_module_value))
    return;

  JS_FreeValue (self->core->ctx, self->main_module_value);
  self->main_module_value = JS_UNINITIALIZED;
}

void
_gum_quick_process_finalize (GumQuickProcess * self)
{
}

static GumQuickProcess *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "process");
}

GUMJS_DEFINE_GETTER (gumjs_process_get_main_module)
{
  GumQuickProcess * self;

  self = gumjs_get_parent_module (core);

  if (JS_IsUninitialized (self->main_module_value))
  {
    self->main_module_value = _gum_quick_module_new (ctx,
        gum_process_get_main_module (), self->module);
  }

  return JS_DupValue (ctx, self->main_module_value);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_dir)
{
  JSValue result;
  gchar * dir_opsys, * dir_utf8;

  dir_opsys = g_get_current_dir ();
  dir_utf8 = g_filename_display_name (dir_opsys);
  result = JS_NewString (ctx, dir_utf8);
  g_free (dir_utf8);
  g_free (dir_opsys);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_home_dir)
{
  JSValue result;
  gchar * dir;

  dir = g_filename_display_name (g_get_home_dir ());
  result = JS_NewString (ctx, dir);
  g_free (dir);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_tmp_dir)
{
  JSValue result;
  gchar * dir;

  dir = g_filename_display_name (g_get_tmp_dir ());
  result = JS_NewString (ctx, dir);
  g_free (dir);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  return JS_NewBool (ctx, gum_process_is_debugger_attached ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  return JS_NewInt64 (ctx, gum_process_get_current_thread_id ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->parent->core;
  JSValue thread, result;

  thread = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, id),
      JS_NewInt64 (ctx, details->id),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, state),
      _gum_quick_thread_state_new (ctx, details->state),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, context),
      _gum_quick_cpu_context_new (ctx, (GumCpuContext *) &details->cpu_context,
          GUM_CPU_CONTEXT_READONLY, core, NULL),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &thread);

  JS_FreeValue (ctx, thread);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  GumQuickFindModuleByNameContext fc;
  gchar * allocated_name = NULL;

  if (!_gum_quick_args_parse (args, "s", &fc.name))
    return JS_EXCEPTION;
  fc.name_is_canonical = g_path_is_absolute (fc.name);
  fc.result = JS_NULL;
  fc.ctx = ctx;
  fc.module = gumjs_get_parent_module (core)->module;

#ifdef HAVE_WINDOWS
  allocated_name = g_utf8_casefold (fc.name, -1);
  fc.name = allocated_name;
#endif

  gum_process_enumerate_modules (
      (GumFoundModuleFunc) gum_store_module_if_name_matches, &fc);

  g_free (allocated_name);

  return fc.result;
}

static gboolean
gum_store_module_if_name_matches (const GumModuleDetails * details,
                                  GumQuickFindModuleByNameContext * fc)
{
  gboolean proceed = TRUE;
  const gchar * key;
  gchar * allocated_key = NULL;

  key = fc->name_is_canonical ? details->path : details->name;

#ifdef HAVE_WINDOWS
  allocated_key = g_utf8_casefold (key, -1);
  key = allocated_key;
#endif

  if (strcmp (key, fc->name) == 0)
  {
    fc->result = _gum_quick_module_new (fc->ctx, details, fc->module);

    proceed = FALSE;
  }

  g_free (allocated_key);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue module, result;

  module = _gum_quick_module_new (ctx, details, mc->parent->module);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &module);

  JS_FreeValue (ctx, module);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_range_by_address)
{
  GumQuickFindRangeByAddressContext fc;
  gpointer ptr;

  if (!_gum_quick_args_parse (args, "p", &ptr))
    return JS_EXCEPTION;
  fc.address = GUM_ADDRESS (ptr);
  fc.result = JS_NULL;
  fc.ctx = ctx;
  fc.core = core;

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS,
      (GumFoundRangeFunc) gum_store_range_if_containing_address, &fc);

  return fc.result;
}

static gboolean
gum_store_range_if_containing_address (const GumRangeDetails * details,
                                       GumQuickFindRangeByAddressContext * fc)
{
  gboolean proceed = TRUE;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, fc->address))
  {
    fc->result = _gum_quick_range_details_new (fc->ctx, details, fc->core);

    proceed = FALSE;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumQuickMatchContext mc;
  GumPageProtection prot;

  if (!_gum_quick_args_parse (args, "mF{onMatch,onComplete}", &prot,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue range, result;

  range = _gum_quick_range_details_new (ctx, details, mc->parent->core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &range);

  JS_FreeValue (ctx, range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_system_ranges)
{
  JSValue ranges = JS_NewObject (ctx);

#ifdef HAVE_DARWIN
  {
    GumMemoryRange dsc;

    if (gum_darwin_query_shared_cache_range (mach_task_self (), &dsc))
    {
      JS_DefinePropertyValueStr (ctx, ranges, "dyldSharedCache",
          _gum_quick_memory_range_new (ctx, &dsc, args->core),
          JS_PROP_C_W_E);
    }
  }
#endif

  return ranges;
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumQuickMatchContext * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->parent->core;
  JSValue range, result;

  range = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, range,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_native_pointer_new (ctx,
          GSIZE_TO_POINTER (details->range->base_address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, range,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, details->range->size),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &range);

  JS_FreeValue (ctx, range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  return _gum_quick_throw_literal (ctx,
      "not yet implemented for " GUM_SCRIPT_PLATFORM);
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumQuickProcess * self;
  JSValue callback;
  GumQuickExceptionHandler * new_handler, * old_handler;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "F?", &callback))
    return JS_EXCEPTION;

  new_handler = !JS_IsNull (callback)
      ? gum_quick_exception_handler_new (callback, self->core)
      : NULL;

  old_handler = self->exception_handler;
  self->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_quick_exception_handler_free (old_handler);

  return JS_UNDEFINED;
}

static GumQuickExceptionHandler *
gum_quick_exception_handler_new (JSValue callback,
                                 GumQuickCore * core)
{
  GumQuickExceptionHandler * handler;

  handler = g_slice_new (GumQuickExceptionHandler);
  handler->callback = JS_DupValue (core->ctx, callback);
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_quick_exception_handler_free (GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;

  gum_exceptor_remove (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  JS_FreeValue (core->ctx, handler->callback);

  g_slice_free (GumQuickExceptionHandler, handler);
}

static gboolean
gum_quick_exception_handler_on_exception (GumExceptionDetails * details,
                                          GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;
  JSContext * ctx = core->ctx;
  gboolean handled;
  GumQuickScope scope;
  JSValue d, r;
  GumQuickCpuContext * cpu_context;

  if (gum_quick_script_backend_is_scope_mutex_trapped (core->backend))
    return FALSE;

  _gum_quick_scope_enter (&scope, core);

  d = _gum_quick_exception_details_new (ctx, details, core, &cpu_context);

  r = _gum_quick_scope_call (&scope, handler->callback, JS_UNDEFINED, 1, &d);

  handled = JS_IsBool (r) && JS_VALUE_GET_BOOL (r);

  _gum_quick_cpu_context_make_read_only (cpu_context);

  JS_FreeValue (ctx, r);
  JS_FreeValue (ctx, d);

  _gum_quick_scope_leave (&scope);

  return handled;
}
