/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscprocess.h"

#include "gumjscmacros.h"

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
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (G_OS_WIN32)
# define GUM_SCRIPT_PLATFORM "windows"
#elif defined (HAVE_QNX)
# define GUM_SCRIPT_PLATFORM "qnx"
#endif

typedef struct _GumJscMatchContext GumJscMatchContext;

struct _GumJscExceptionHandler
{
  JSObjectRef callback;
  GumJscCore * core;
};

struct _GumJscMatchContext
{
  GumJscProcess * self;
  JSObjectRef on_match;
  JSObjectRef on_complete;
  JSContextRef ctx;
};

GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    gpointer user_data);
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumJscExceptionHandler * gum_jsc_exception_handler_new (
    JSObjectRef callback, GumJscCore * core);
static void gum_jsc_exception_handler_free (
    GumJscExceptionHandler * handler);
static gboolean gum_jsc_exception_handler_on_exception (
    GumExceptionDetails * details, gpointer user_data);

static const JSStaticFunction gumjs_process_functions[] =
{
  { "isDebuggerAttached", gumjs_process_is_debugger_attached, GUMJS_RO },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id, GUMJS_RO },
  { "enumerateThreads", gumjs_process_enumerate_threads, GUMJS_RO },
  { "enumerateModules", gumjs_process_enumerate_modules, GUMJS_RO },
  { "_enumerateRanges", gumjs_process_enumerate_ranges, GUMJS_RO },
  { "enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges, GUMJS_RO },
  { "setExceptionHandler", gumjs_process_set_exception_handler, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_jsc_process_init (GumJscProcess * self,
                       GumJscCore * core,
                       JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef process;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Process";
  def.staticFunctions = gumjs_process_functions;
  klass = JSClassCreate (&def);
  process = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);

  _gumjs_object_set_string (ctx, process, "arch", GUM_SCRIPT_ARCH);
  _gumjs_object_set_string (ctx, process, "platform", GUM_SCRIPT_PLATFORM);
  _gumjs_object_set_uint (ctx, process, "pageSize", gum_query_page_size ());
  _gumjs_object_set_uint (ctx, process, "pointerSize", GLIB_SIZEOF_VOID_P);

  _gumjs_object_set (ctx, scope, def.className, process);
}

void
_gum_jsc_process_dispose (GumJscProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_jsc_exception_handler_free);
}

void
_gum_jsc_process_finalize (GumJscProcess * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  return JSValueMakeBoolean (ctx,
      gum_process_is_debugger_attached () ? true : false);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  return JSValueMakeNumber (ctx, gum_process_get_current_thread_id ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumJscMatchContext mc;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_process_enumerate_threads (gum_emit_thread, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 gpointer user_data)
{
  GumJscMatchContext * mc = user_data;
  GumJscCore * core = mc->self->core;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef thread;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (core->backend),
      details->id))
    return TRUE;

  thread = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_uint (ctx, thread, "id", details->id);
  _gumjs_object_set_string (ctx, thread, "state",
      _gumjs_thread_state_to_string (details->state));
  _gumjs_object_set (ctx, thread, "context", _gumjs_cpu_context_new (ctx,
      (GumCpuContext *) &details->cpu_context, GUM_CPU_CONTEXT_READONLY, core));

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &thread, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumJscMatchContext mc;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_process_enumerate_modules (gum_emit_module, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 gpointer user_data)
{
  GumJscMatchContext * mc = user_data;
  GumJscCore * core = mc->self->core;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef module;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  module = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_string (ctx, module, "name", details->name);
  _gumjs_object_set_pointer (ctx, module, "base",
      GSIZE_TO_POINTER (details->range->base_address), core);
  _gumjs_object_set_uint (ctx, module, "size", details->range->size);
  _gumjs_object_set_string (ctx, module, "path", details->path);

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &module, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumJscMatchContext mc;
  GumPageProtection prot;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_process_enumerate_ranges (prot, gum_emit_range, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                gpointer user_data)
{
  GumJscMatchContext * mc = user_data;
  GumJscCore * core = mc->self->core;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  char prot_str[4] = "---";
  JSObjectRef range;
  const GumFileMapping * f = details->file;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  range = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_pointer (ctx, range, "base",
      GSIZE_TO_POINTER (details->range->base_address), core);
  _gumjs_object_set_uint (ctx, range, "size", details->range->size);
  _gumjs_object_set_string (ctx, range, "protection", prot_str);

  if (f != NULL)
  {
    JSObjectRef file = JSObjectMake (ctx, NULL, NULL);
    _gumjs_object_set_string (ctx, file, "path", f->path);
    _gumjs_object_set_uint (ctx, file, "offset", f->offset);
    _gumjs_object_set (ctx, range, "file", file);
  }

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &range, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
#ifdef HAVE_DARWIN
  GumJscMatchContext mc;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_process_enumerate_malloc_ranges (gum_emit_malloc_range, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
#else
  _gumjs_throw (ctx, exception, "not implemented yet for " GUM_SCRIPT_PLATFORM);
  return NULL;
#endif
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       gpointer user_data)
{
  GumJscMatchContext * mc = user_data;
  GumJscCore * core = mc->self->core;
  GumJscScope scope = GUM_JSC_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef range;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  range = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_pointer (ctx, range, "base",
      GSIZE_TO_POINTER (details->range->base_address), core);
  _gumjs_object_set_uint (ctx, range, "size", details->range->size);

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &range, &scope.exception);
  _gum_jsc_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumJscProcess * self;
  GumJscCore * core;
  JSObjectRef callback;
  GumJscExceptionHandler * new_handler, * old_handler;

  self = JSObjectGetPrivate (this_object);
  core = self->core;

  if (!_gumjs_args_parse (args, "F?", &callback))
    return NULL;

  new_handler = (callback != NULL)
      ? gum_jsc_exception_handler_new (callback, core)
      : NULL;

  GUM_JSC_CORE_LOCK (core);
  old_handler = self->exception_handler;
  self->exception_handler = new_handler;
  GUM_JSC_CORE_UNLOCK (core);

  if (old_handler != NULL)
    gum_jsc_exception_handler_free (old_handler);

  return JSValueMakeUndefined (ctx);
}

static GumJscExceptionHandler *
gum_jsc_exception_handler_new (JSObjectRef callback,
                               GumJscCore * core)
{
  GumJscExceptionHandler * handler;

  handler = g_slice_new (GumJscExceptionHandler);
  JSValueProtect (core->ctx, callback);
  handler->callback = callback;
  handler->core = core;

  gum_exceptor_add (core->exceptor, gum_jsc_exception_handler_on_exception,
      handler);

  return handler;
}

static void
gum_jsc_exception_handler_free (GumJscExceptionHandler * handler)
{
  gum_exceptor_remove (handler->core->exceptor,
      gum_jsc_exception_handler_on_exception, handler);

  JSValueUnprotect (handler->core->ctx, handler->callback);

  g_slice_free (GumJscExceptionHandler, handler);
}

static gboolean
gum_jsc_exception_handler_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumJscExceptionHandler * handler = user_data;
  GumJscCore * core = handler->core;
  GumJscScope scope;
  JSContextRef ctx = core->ctx;
  JSObjectRef exception, cpu_context;
  JSValueRef result;
  gboolean handled;

  _gum_jsc_scope_enter (&scope, core);

  _gumjs_parse_exception_details (ctx, details, core, &exception, &cpu_context);

  result = JSObjectCallAsFunction (ctx, handler->callback, NULL, 1,
      (JSValueRef *) &exception, &scope.exception);

  _gumjs_cpu_context_detach (cpu_context);

  handled = FALSE;
  if (result != NULL)
    _gumjs_boolean_try_get (ctx, result, &handled, NULL);

  _gum_jsc_scope_leave (&scope);

  return handled;
}
