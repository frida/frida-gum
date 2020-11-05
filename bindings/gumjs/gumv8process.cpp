/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8process.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"
#include "gumv8scope.h"
#ifdef HAVE_DARWIN
# include <gumdarwin.h>
#endif

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
#elif defined (HAVE_WINDOWS)
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

struct GumV8FindModuleByNameContext
{
  gchar * name;
  gboolean name_is_canonical;

  Local<Object> module;

  GumV8Process * parent;
};

GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
static gboolean gum_store_module_if_name_matches (
    const GumModuleDetails * details, GumV8FindModuleByNameContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_system_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumV8ExceptionHandler * gum_v8_exception_handler_new (
    Local<Function> callback, GumV8Core * core);
static void gum_v8_exception_handler_free (
    GumV8ExceptionHandler * handler);
static gboolean gum_v8_exception_handler_on_exception (
    GumExceptionDetails * details, GumV8ExceptionHandler * handler);

const gchar * gum_v8_script_exception_type_to_string (GumExceptionType type);

static const GumV8Function gumjs_process_functions[] =
{
  { "isDebuggerAttached", gumjs_process_is_debugger_attached },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id },
  { "_enumerateThreads", gumjs_process_enumerate_threads },
  { "findModuleByName", gumjs_process_find_module_by_name },
  { "_enumerateModules", gumjs_process_enumerate_modules },
  { "_enumerateRanges", gumjs_process_enumerate_ranges },
  { "enumerateSystemRanges", gumjs_process_enumerate_system_ranges },
  { "_enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges },
  { "setExceptionHandler", gumjs_process_set_exception_handler },

  { NULL, NULL }
};

void
_gum_v8_process_init (GumV8Process * self,
                      GumV8Module * module,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->module = module;
  self->core = core;

  auto process = _gum_v8_create_module ("Process", scope, isolate);
  process->Set (_gum_v8_string_new_ascii (isolate, "id"),
      Number::New (isolate, gum_process_get_id ()), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "arch"),
      String::NewFromUtf8Literal (isolate, GUM_SCRIPT_ARCH), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "platform"),
      String::NewFromUtf8Literal (isolate, GUM_SCRIPT_PLATFORM), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pageSize"),
      Number::New (isolate, gum_query_page_size ()), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pointerSize"),
      Number::New (isolate, GLIB_SIZEOF_VOID_P), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "codeSigningPolicy"),
      String::NewFromUtf8 (isolate, gum_code_signing_policy_to_string (
      gum_process_get_code_signing_policy ())).ToLocalChecked (), ReadOnly);
  _gum_v8_module_add (External::New (isolate, self), process,
      gumjs_process_functions, isolate);
}

void
_gum_v8_process_realize (GumV8Process * self)
{
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
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  info.GetReturnValue ().Set (!!gum_process_is_debugger_attached ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  info.GetReturnValue ().Set ((uint32_t) gum_process_get_current_thread_id ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumV8MatchContext<GumV8Process> * mc)
{
  auto core = mc->parent->core;
  auto isolate = core->isolate;

  auto thread = Object::New (isolate);
  _gum_v8_object_set (thread, "id", Number::New (isolate, details->id), core);
  _gum_v8_object_set (thread, "state", _gum_v8_string_new_ascii (isolate,
      _gum_v8_thread_state_to_string (details->state)), core);
  auto cpu_context =
      _gum_v8_cpu_context_new_immutable (&details->cpu_context, core);
  _gum_v8_object_set (thread, "context", cpu_context, core);

  auto proceed = mc->OnMatch (thread);

  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, cpu_context), core);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  GumV8FindModuleByNameContext fc;
  if (!_gum_v8_args_parse (args, "s", &fc.name))
    return;
  fc.name_is_canonical = g_path_is_absolute (fc.name);
  fc.parent = module;

#ifdef HAVE_WINDOWS
  gchar * folded_name = g_utf8_casefold (fc.name, -1);
  g_free (fc.name);
  fc.name = folded_name;
#endif

  gum_process_enumerate_modules (
      (GumFoundModuleFunc) gum_store_module_if_name_matches, &fc);

  if (!fc.module.IsEmpty ())
    info.GetReturnValue ().Set (fc.module);
  else
    info.GetReturnValue ().SetNull ();

  g_free (fc.name);
}

static gboolean
gum_store_module_if_name_matches (const GumModuleDetails * details,
                                  GumV8FindModuleByNameContext * fc)
{
  gboolean proceed = TRUE;

  const gchar * key = fc->name_is_canonical ? details->path : details->name;
  gchar * allocated_key = NULL;

#ifdef HAVE_WINDOWS
  allocated_key = g_utf8_casefold (key, -1);
  key = allocated_key;
#endif

  if (strcmp (key, fc->name) == 0)
  {
    fc->module = _gum_v8_module_value_new (details, fc->parent->module);

    proceed = FALSE;
  }

  g_free (allocated_key);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumV8MatchContext<GumV8Process> * mc)
{
  auto module = _gum_v8_module_value_new (details, mc->parent->module);

  return mc->OnMatch (module);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumPageProtection prot;
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext<GumV8Process> * mc)
{
  auto core = mc->parent->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  auto f = details->file;
  if (f != NULL)
  {
    auto file = Object::New (isolate);
    _gum_v8_object_set_utf8 (file, "path", f->path, core);
    _gum_v8_object_set_uint (file, "offset", f->offset, core);
    _gum_v8_object_set_uint (file, "size", f->size, core);
    _gum_v8_object_set (range, "file", file, core);
  }

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_system_ranges)
{
  auto ranges = Object::New (isolate);

#ifdef HAVE_DARWIN
  {
    GumMemoryRange dsc;

    if (gum_darwin_query_shared_cache_range (mach_task_self (), &dsc))
    {
      auto range = Object::New (isolate);
      _gum_v8_object_set_pointer (range, "base", dsc.base_address, core);
      _gum_v8_object_set_uint (range, "size", dsc.size, core);
      _gum_v8_object_set (ranges, "dyldSharedCache", range, core);
    }
  }
#endif

  info.GetReturnValue ().Set (ranges);
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumV8MatchContext<GumV8Process> * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumV8MatchContext<GumV8Process> * mc)
{
  auto core = mc->parent->core;

  auto range = Object::New (mc->isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);

  return mc->OnMatch (range);
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  _gum_v8_throw_ascii_literal (isolate,
      "not yet implemented for " GUM_SCRIPT_PLATFORM);
}

#endif

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
gum_v8_exception_handler_new (Local<Function> callback,
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

  if (gum_v8_script_backend_is_scope_mutex_trapped (core->backend))
    return FALSE;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  auto callback = Local<Function>::New (isolate, *handler->callback);

  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);

  gboolean handled = FALSE;
  Local<Value> argv[] = { ex };
  Local<Value> result;
  if (callback->Call (isolate->GetCurrentContext (), Undefined (isolate),
      G_N_ELEMENTS (argv), argv).ToLocal (&result))
  {
    if (result->IsBoolean ())
      handled = result.As<Boolean> ()->Value ();
  }

  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, context), core);

  return handled;
}
