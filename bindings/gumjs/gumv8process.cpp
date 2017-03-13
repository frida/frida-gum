/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8process.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <string.h>

#define GUMJS_MODULE_NAME Process

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

using namespace v8;

struct GumV8ExceptionHandler
{
  GumPersistent<Function>::type * callback;

  GumV8Core * core;
};

struct GumV8MatchContext
{
  Local<Function> on_match;
  Local<Function> on_complete;

  GumV8Core * core;

  gboolean has_pending_exception;
};

GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumV8ExceptionHandler * gum_v8_exception_handler_new (
    Handle<Function> callback, GumV8Core * core);
static void gum_v8_exception_handler_free (
    GumV8ExceptionHandler * handler);
static gboolean gum_v8_exception_handler_on_exception (
    GumExceptionDetails * details, GumV8ExceptionHandler * handler);

const gchar * gum_v8_script_exception_type_to_string (GumExceptionType type);

static const GumV8Function gumjs_process_functions[] =
{
  { "isDebuggerAttached", gumjs_process_is_debugger_attached },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id },
  { "enumerateThreads", gumjs_process_enumerate_threads },
  { "enumerateModules", gumjs_process_enumerate_modules },
  { "_enumerateRanges", gumjs_process_enumerate_ranges },
  { "enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges },
  { "setExceptionHandler", gumjs_process_set_exception_handler },

  { NULL, NULL }
};

void
_gum_v8_process_init (GumV8Process * self,
                      GumV8Core * core,
                      Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto process = _gum_v8_create_module ("Process", scope, isolate);
  process->Set (_gum_v8_string_new_ascii (isolate, "arch"),
      String::NewFromUtf8 (isolate, GUM_SCRIPT_ARCH), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "platform"),
      String::NewFromUtf8 (isolate, GUM_SCRIPT_PLATFORM), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pageSize"),
      Number::New (isolate, gum_query_page_size ()), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pointerSize"),
      Number::New (isolate, GLIB_SIZEOF_VOID_P), ReadOnly);
  _gum_v8_module_add (module, process, gumjs_process_functions, isolate);
}

void
_gum_v8_process_realize (GumV8Process * self)
{
  (void) self;
}

void
_gum_v8_process_flush (GumV8Process * self)
{
  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);
}

void
_gum_v8_process_dispose (GumV8Process * self)
{
  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);
}

void
_gum_v8_process_finalize (GumV8Process * self)
{
  (void) self;
}

/*
 * Prototype:
 * Process.isDebuggerAttached()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  info.GetReturnValue ().Set (!!gum_process_is_debugger_attached ());
}

/*
 * Prototype:
 * Process.getCurrentThreadId()
 *
 * Docs:
 * Returns the current thread ID as an unsigned 32-bit integer.
 *
 * Example:
 * -> Process.getCurrentThreadId()
 * 3075
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  info.GetReturnValue ().Set ((uint32_t) gum_process_get_current_thread_id ());
}

/*
 * Prototype:
 * Process.enumerateThreads(callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto thread = Object::New (isolate);
  _gum_v8_object_set (thread, "id", Number::New (isolate, details->id), core);
  _gum_v8_object_set (thread, "state", _gum_v8_string_new_ascii (isolate,
      _gum_v8_thread_state_to_string (details->state)), core);
  auto cpu_context = _gum_v8_cpu_context_new (&details->cpu_context, core);
  _gum_v8_object_set (thread, "context", cpu_context, core);

  Handle<Value> argv[] = { thread };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, cpu_context), core);

  return proceed;
}

/*
 * Prototype:
 * Process.enumerateModules(callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto module = Object::New (isolate);
  _gum_v8_object_set_ascii (module, "name", details->name, core);
  _gum_v8_object_set_pointer (module, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (module, "size", details->range->size, core);
  _gum_v8_object_set_utf8 (module, "path", details->path, core);

  Handle<Value> argv[] = { module };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

/*
 * Prototype:
 * Process._enumerateRanges(prot, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumPageProtection prot;
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_ascii (range, "protection", prot_str, core);

  auto f = details->file;
  if (f != NULL)
  {
    auto file = Object::New (isolate);
    _gum_v8_object_set_utf8 (file, "path", f->path, core);
    _gum_v8_object_set_uint (file, "offset", f->offset, core);
    _gum_v8_object_set (range, "file", file, core);
  }

  Handle<Value> argv[] = { range };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

/*
 * Prototype:
 * Process.enumerateMallocRanges(callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */

#ifdef HAVE_DARWIN

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumV8MatchContext * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumV8MatchContext mc;
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;
  mc.core = core;

  mc.has_pending_exception = FALSE;

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);

  if (!mc.has_pending_exception)
  {
    mc.on_complete->Call (Undefined (isolate), 0, nullptr);
  }
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumV8MatchContext * mc)
{
  auto core = mc->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);

  Handle<Value> argv[] = { range };
  auto result =
      mc->on_match->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  mc->has_pending_exception = result.IsEmpty ();

  gboolean proceed = !mc->has_pending_exception;
  if (proceed && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  _gum_v8_throw_ascii_literal (isolate,
      "not yet implemented for " GUM_SCRIPT_PLATFORM);
}

#endif

/*
 * Prototype:
 * Process.setExceptionHandler(callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_handler = !callback.IsEmpty ()
      ? gum_v8_exception_handler_new (callback, core)
      : NULL;

  auto old_handler = module->exception_handler;
  module->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_v8_exception_handler_free (old_handler);
}

static GumV8ExceptionHandler *
gum_v8_exception_handler_new (Handle<Function> callback,
                              GumV8Core * core)
{
  auto handler = g_slice_new (GumV8ExceptionHandler);
  handler->callback =
      new GumPersistent<Function>::type (core->isolate, callback);
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_v8_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_v8_exception_handler_free (GumV8ExceptionHandler * handler)
{
  gum_exceptor_remove (handler->core->exceptor,
      (GumExceptionHandler) gum_v8_exception_handler_on_exception, handler);

  delete handler->callback;

  g_slice_free (GumV8ExceptionHandler, handler);
}

static gboolean
gum_v8_exception_handler_on_exception (GumExceptionDetails * details,
                                       GumV8ExceptionHandler * handler)
{
  auto core = handler->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  auto callback = Local<Function>::New (isolate, *handler->callback);

  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);

  Handle<Value> argv[] = { ex };
  auto result = callback->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, context), core);

  if (!result.IsEmpty () && result->IsBoolean ())
  {
    bool handled = result.As<Boolean> ()->Value ();
    return handled ? TRUE : FALSE;
  }

  return FALSE;
}
