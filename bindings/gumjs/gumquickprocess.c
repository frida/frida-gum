/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

  GumQuickScope * scope;
  GumQuickProcess * module;
};

struct _GumQuickFindModuleByNameContext
{
  const gchar * name;
  gboolean name_is_canonical;

  GumQuickProcess * module;
};

struct _GumQuickFindRangeByAddressContext
{
  GumAddress address;

  GumQuickCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
static gboolean gum_push_module_if_name_matches (
    const GumModuleDetails * details, GumQuickFindModuleByNameContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_range_by_address)
static gboolean gum_push_range_if_containing_address (
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
  GUMJS_EXPORT_CFUNC ("isDebuggerAttached",
      0, gumjs_process_is_debugger_attached),
  GUMJS_EXPORT_CFUNC ("getCurrentThreadId",
      0, gumjs_process_get_current_thread_id),
  GUMJS_EXPOSE_CFUNC ("_enumerateThreads",
      0, gumjs_process_enumerate_threads),
  GUMJS_EXPORT_CFUNC ("findModuleByName",
      0, gumjs_process_find_module_by_name),
  GUMJS_EXPOSE_CFUNC ("_enumerateModules",
      0, gumjs_process_enumerate_modules),
  GUMJS_EXPORT_CFUNC ("findRangeByAddress",
      0, gumjs_process_find_range_by_address),
  GUMJS_EXPOSE_CFUNC ("_enumerateRanges",
      0, gumjs_process_enumerate_ranges),
  GUMJS_EXPORT_CFUNC ("enumerateSystemRanges",
      0, gumjs_process_enumerate_system_ranges),
  GUMJS_EXPOSE_CFUNC ("_enumerateMallocRanges",
      0, gumjs_process_enumerate_malloc_ranges),
  GUMJS_EXPORT_CFUNC ("setExceptionHandler",
      0, gumjs_process_set_exception_handler),
};

void
_gum_quick_process_init (GumQuickProcess * self,
                         GumQuickModule * module,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj;

  self->module = module;
  self->core = core;

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
}

void
_gum_quick_process_dispose (GumQuickProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_quick_exception_handler_free);
}

void
_gum_quick_process_finalize (GumQuickProcess * self)
{
}

static GumQuickThread *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "process");
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  quick_push_boolean (ctx,
      gum_process_is_debugger_attached () ? TRUE : FALSE);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  quick_push_number (ctx, gum_process_get_current_thread_id ());
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumQuickMatchContext mc;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (args->core);

  _gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;
  mc.module = gumjs_module_from_args (args);

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);

  quick_push_object (ctx);
  quick_push_uint (ctx, details->id);
  quick_put_prop_string (ctx, -2, "id");
  quick_push_string (ctx, _gum_quick_thread_state_to_string (details->state));
  quick_put_prop_string (ctx, -2, "state");
  _gum_quick_push_cpu_context (ctx, (GumCpuContext *) &details->cpu_context,
      GUM_CPU_CONTEXT_READONLY, scope->core);
  quick_put_prop_string (ctx, -2, "context");

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  GumQuickFindModuleByNameContext fc;
  gchar * allocated_name = NULL;

  _gum_quick_args_parse (args, "s", &fc.name);
  fc.name_is_canonical = g_path_is_absolute (fc.name);
  fc.module = gumjs_module_from_args (args);

#ifdef HAVE_WINDOWS
  allocated_name = g_utf8_casefold (fc.name, -1);
  fc.name = allocated_name;
#endif

  quick_push_null (ctx);

  gum_process_enumerate_modules (
      (GumFoundModuleFunc) gum_push_module_if_name_matches, &fc);

  g_free (allocated_name);

  return 1;
}

static gboolean
gum_push_module_if_name_matches (const GumModuleDetails * details,
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
    GumQuickProcess * module = fc->module;
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (module->core);
    JSContext * ctx = scope.ctx;

    quick_pop (ctx);
    _gum_quick_push_module (ctx, details, module->module);

    proceed = FALSE;
  }

  g_free (allocated_key);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumQuickMatchContext mc;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (args->core);

  _gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;
  mc.module = gumjs_module_from_args (args);

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);
  _gum_quick_push_module (ctx, details, mc->module->module);

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_range_by_address)
{
  GumQuickFindRangeByAddressContext fc;
  gpointer ptr;

  _gum_quick_args_parse (args, "p", &ptr);

  fc.address = GUM_ADDRESS (ptr);
  fc.core = args->core;

  quick_push_null (ctx);

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS,
      (GumFoundRangeFunc) gum_push_range_if_containing_address, &fc);

  return 1;
}

static gboolean
gum_push_range_if_containing_address (const GumRangeDetails * details,
                                      GumQuickFindRangeByAddressContext * fc)
{
  gboolean proceed = TRUE;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, fc->address))
  {
    GumQuickScope scope = GUM_QUICK_SCOPE_INIT (fc->core);
    JSContext * ctx = scope.ctx;

    quick_pop (ctx);
    _gum_quick_push_range_details (ctx, details, fc->core);

    proceed = FALSE;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumQuickMatchContext mc;
  GumPageProtection prot;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (args->core);

  _gum_quick_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;
  mc.module = gumjs_module_from_args (args);

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);
  _gum_quick_push_range_details (ctx, details, scope->core);

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_system_ranges)
{
  quick_push_object (ctx);

#ifdef HAVE_DARWIN
  {
    GumMemoryRange dsc;

    if (gum_darwin_query_shared_cache_range (mach_task_self (), &dsc))
    {
      _gum_quick_push_memory_range (ctx, &dsc, args->core);
      quick_put_prop_string (ctx, -2, "dyldSharedCache");
    }
  }
#endif

  return 1;
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumQuickMatchContext * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumQuickMatchContext mc;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (args->core);

  _gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;
  mc.module = gumjs_module_from_args (args);

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);
  _gum_quick_scope_flush (&scope);

  quick_push_heapptr (ctx, mc.on_complete);
  quick_call (ctx, 0);
  quick_pop (ctx);

  return 0;
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumQuickMatchContext * mc)
{
  GumQuickScope * scope = mc->scope;
  JSContext * ctx = scope->ctx;
  gboolean proceed = TRUE;

  quick_push_heapptr (ctx, mc->on_match);

  quick_push_object (ctx);

  _gum_quick_push_native_pointer (ctx,
      GSIZE_TO_POINTER (details->range->base_address), scope->core);
  quick_put_prop_string (ctx, -2, "base");

  quick_push_uint (ctx, details->range->size);
  quick_put_prop_string (ctx, -2, "size");

  if (_gum_quick_scope_call_sync (scope, 1))
  {
    if (quick_is_string (ctx, -1))
      proceed = strcmp (quick_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  quick_pop (ctx);

  return proceed;
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  _gum_quick_throw (ctx, "not yet implemented for " GUM_SCRIPT_PLATFORM);
  return 0;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumQuickProcess * self;
  JSValue callback;
  GumQuickExceptionHandler * new_handler, * old_handler;

  self = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "F?", &callback);

  new_handler = (callback != NULL)
      ? gum_quick_exception_handler_new (callback, self->core)
      : NULL;

  old_handler = self->exception_handler;
  self->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_quick_exception_handler_free (old_handler);

  return 0;
}

static GumQuickExceptionHandler *
gum_quick_exception_handler_new (JSValue callback,
                                 GumQuickCore * core)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumQuickExceptionHandler * handler;

  handler = g_slice_new (GumQuickExceptionHandler);
  _gum_quick_protect (scope.ctx, callback);
  handler->callback = callback;
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_quick_exception_handler_free (GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  gum_exceptor_remove (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  _gum_quick_unprotect (scope.ctx, handler->callback);

  g_slice_free (GumQuickExceptionHandler, handler);
}

static gboolean
gum_quick_exception_handler_on_exception (GumExceptionDetails * details,
                                          GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;
  GumQuickScope scope;
  JSContext * ctx;
  GumQuickCpuContext * cpu_context;
  gboolean handled = FALSE;

  ctx = _gum_quick_scope_enter (&scope, core);

  _gum_quick_push_exception_details (ctx, details, core, &cpu_context);

  quick_push_heapptr (ctx, handler->callback);
  quick_dup (ctx, -2);
  if (_gum_quick_scope_call (&scope, 1))
  {
    if (quick_is_boolean (ctx, -1))
      handled = quick_require_boolean (ctx, -1);
  }

  _gum_quick_cpu_context_make_read_only (cpu_context);

  quick_pop_2 (ctx);

  _gum_quick_scope_leave (&scope);

  return handled;
}
