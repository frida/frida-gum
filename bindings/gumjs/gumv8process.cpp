/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8process.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"
#include "gumv8scope.h"

#include <string.h>
#ifdef HAVE_DARWIN
# include <gum/gumdarwin.h>
#endif

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

using namespace v8;

struct GumV8ExceptionHandler
{
  Global<Function> * callback;

  GumV8Core * core;
};

struct GumV8RunOnThreadContext
{
  Global<Function> * user_func;

  GumV8Core * core;
};

struct GumV8ModuleObserver
{
  gint ref_count;

  Global<Function> * on_added;
  Global<Function> * on_removed;
  Global<Object> * resource;

  gulong added_handler;
  gulong removed_handler;

  GumV8Process * parent;
};

GUMJS_DECLARE_GETTER (gumjs_process_get_main_module)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_home_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_tmp_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_run_on_thread)
static void gum_v8_run_on_thread_context_free (GumV8RunOnThreadContext * rc);
static void gum_do_call_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static void gum_v8_process_maybe_start_stalker_gc_timer (GumV8Process * self);
static gboolean gum_v8_process_on_stalker_gc_timer_tick (GumV8Process * self);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_address)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (GumModule * module,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_attach_module_observer)
static GumV8ModuleObserver * gum_v8_module_observer_ref (
    GumV8ModuleObserver * observer);
static void gum_v8_module_observer_unref (GumV8ModuleObserver * observer);
static void gum_v8_module_observer_destroy (GumV8ModuleObserver * self);
static gboolean gum_emit_existing_module (GumModule * module,
    GumV8ModuleObserver * observer);
static void gum_emit_added_module (GumModuleRegistry * registry,
    GumModule * module, GumV8ModuleObserver * observer);
static void gum_emit_removed_module (GumModuleRegistry * registry,
    GumModule * module, GumV8ModuleObserver * observer);
static void gum_v8_module_observer_invoke (GumV8ModuleObserver * self,
    Global<Function> * callback, GumModule * module);
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

GUMJS_DECLARE_FUNCTION (gumjs_module_observer_detach)

static const GumV8Property gumjs_process_values[] =
{
  { "mainModule", gumjs_process_get_main_module, NULL },

  { NULL, NULL }
};

static const GumV8Function gumjs_process_functions[] =
{
  { "getCurrentDir", gumjs_process_get_current_dir },
  { "getHomeDir", gumjs_process_get_home_dir },
  { "getTmpDir", gumjs_process_get_tmp_dir },
  { "isDebuggerAttached", gumjs_process_is_debugger_attached },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id },
  { "_enumerateThreads", gumjs_process_enumerate_threads },
  { "_runOnThread", gumjs_process_run_on_thread },
  { "findModuleByName", gumjs_process_find_module_by_name },
  { "findModuleByAddress", gumjs_process_find_module_by_address },
  { "_enumerateModules", gumjs_process_enumerate_modules },
  { "attachModuleObserver", gumjs_process_attach_module_observer },
  { "_enumerateRanges", gumjs_process_enumerate_ranges },
  { "enumerateSystemRanges", gumjs_process_enumerate_system_ranges },
  { "_enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges },
  { "setExceptionHandler", gumjs_process_set_exception_handler },
  { NULL, NULL }
};

static const GumV8Function gumjs_module_observer_functions[] =
{
  { "detach", gumjs_module_observer_detach },

  { NULL, NULL }
};

void
_gum_v8_process_init (GumV8Process * self,
                      GumV8Module * module,
                      GumV8Thread * thread,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->module = module;
  self->thread = thread;
  self->core = core;

  self->stalker = NULL;

  self->module_observers = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_module_observer_destroy);

  auto process_module = External::New (isolate, self);

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
  _gum_v8_module_add (process_module, process, gumjs_process_values, isolate);
  _gum_v8_module_add (process_module, process,
      gumjs_process_functions, isolate);

  auto observer = _gum_v8_create_class ("ModuleObserver", nullptr, scope,
      process_module, isolate);
  _gum_v8_class_add (observer, gumjs_module_observer_functions, process_module,
      isolate);
  self->module_observer = new Global<FunctionTemplate> (isolate, observer);
}

void
_gum_v8_process_realize (GumV8Process * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto observer = Local<FunctionTemplate>::New (isolate,
      *self->module_observer);
  auto observer_value = observer->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->module_observer_value =
      new Global<Object> (isolate, observer_value);
}

void
_gum_v8_process_flush (GumV8Process * self)
{
  g_hash_table_remove_all (self->module_observers);

  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);

  delete self->main_module_value;
  self->main_module_value = nullptr;

  g_hash_table_remove_all (self->module_observers);
}

void
_gum_v8_process_dispose (GumV8Process * self)
{
  g_assert (self->stalker_gc_timer == NULL);

  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);

  delete self->main_module_value;
  self->main_module_value = nullptr;

  delete self->module_observer_value;
  self->module_observer_value = nullptr;

  delete self->module_observer;
  self->module_observer = nullptr;
}

void
_gum_v8_process_finalize (GumV8Process * self)
{
  g_clear_object (&self->stalker);

  g_hash_table_unref (self->module_observers);
}

GUMJS_DEFINE_GETTER (gumjs_process_get_main_module)
{
  auto self = module;

  if (self->main_module_value == nullptr)
  {
    self->main_module_value = new Global<Object> (isolate,
        _gum_v8_module_new_from_handle (gum_process_get_main_module (),
          self->module));
  }

  info.GetReturnValue ().Set (
      Local<Object>::New (isolate, *module->main_module_value));
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_dir)
{
  gchar * dir_opsys = g_get_current_dir ();
  gchar * dir_utf8 = g_filename_display_name (dir_opsys);
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir_utf8).ToLocalChecked ());
  g_free (dir_utf8);
  g_free (dir_opsys);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_home_dir)
{
  gchar * dir = g_filename_display_name (g_get_home_dir ());
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir).ToLocalChecked ());
  g_free (dir);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_tmp_dir)
{
  gchar * dir = g_filename_display_name (g_get_tmp_dir ());
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir).ToLocalChecked ());
  g_free (dir);
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

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc,
      GUM_THREAD_FLAGS_ALL);

  mc.OnComplete ();
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumV8MatchContext<GumV8Process> * mc)
{
  return mc->OnMatch (_gum_v8_thread_new (details, mc->parent->thread));
}

GUMJS_DEFINE_FUNCTION (gumjs_process_run_on_thread)
{
  GumThreadId thread_id;
  Local<Function> user_func;
  if (!_gum_v8_args_parse (args, "ZF", &thread_id, &user_func))
    return;

  if (module->stalker == NULL)
    module->stalker = gum_stalker_new ();

  auto rc = g_slice_new (GumV8RunOnThreadContext);
  rc->user_func = new Global<Function> (isolate, user_func);
  rc->core = core;

  gboolean success;
  {
    ScriptUnlocker unlocker (core);

    success = gum_stalker_run_on_thread (module->stalker, thread_id,
        gum_do_call_on_thread, rc,
        (GDestroyNotify) gum_v8_run_on_thread_context_free);
  }

  gum_v8_process_maybe_start_stalker_gc_timer (module);

  if (!success)
    _gum_v8_throw_ascii_literal (isolate, "failed to run on thread");

  return;
}

static void
gum_v8_run_on_thread_context_free (GumV8RunOnThreadContext * rc)
{
  ScriptScope scope (rc->core->script);
  delete rc->user_func;

  g_slice_free (GumV8RunOnThreadContext, rc);
}

static void
gum_do_call_on_thread (const GumCpuContext * cpu_context,
                       gpointer user_data)
{
  auto rc = (GumV8RunOnThreadContext *) user_data;
  auto core = rc->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  auto user_func = Local<Function>::New (isolate, *rc->user_func);
  auto result = user_func->Call (isolate->GetCurrentContext (),
      Undefined (isolate), 0, nullptr);
  _gum_v8_ignore_result (result);
}

static void
gum_v8_process_maybe_start_stalker_gc_timer (GumV8Process * self)
{
  GumV8Core * core = self->core;

  if (self->stalker_gc_timer != NULL)
    return;

  if (!gum_stalker_garbage_collect (self->stalker))
    return;

  auto source = g_timeout_source_new (10);
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_process_on_stalker_gc_timer_tick, self, NULL);
  self->stalker_gc_timer = source;

  _gum_v8_core_pin (core);

  {
    ScriptUnlocker unlocker (core);

    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);
  }
}

static gboolean
gum_v8_process_on_stalker_gc_timer_tick (GumV8Process * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumV8Core * core = self->core;

    ScriptScope scope (core->script);

    _gum_v8_core_unpin (core);
    self->stalker_gc_timer = NULL;
  }

  return pending_garbage ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  auto handle = gum_process_find_module_by_name (name);
  if (handle != NULL)
  {
    info.GetReturnValue ().Set (
        _gum_v8_module_new_take_handle (handle, module->module));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_address)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto handle = gum_process_find_module_by_address (GUM_ADDRESS (address));
  if (handle != NULL)
  {
    info.GetReturnValue ().Set (
        _gum_v8_module_new_take_handle (handle, module->module));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
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
gum_emit_module (GumModule * module,
                 GumV8MatchContext<GumV8Process> * mc)
{
  auto wrapper = _gum_v8_module_new_from_handle (module, mc->parent->module);

  return mc->OnMatch (wrapper);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_attach_module_observer)
{
  Local<Function> on_added, on_removed;
  if (!_gum_v8_args_parse (args, "F{onAdded?,onRemoved?}", &on_added,
        &on_removed))
    return;
  auto callback_val = info[0];

  bool observe_added = !on_added.IsEmpty ();
  bool observe_removed = !on_removed.IsEmpty ();

  if (!observe_added && !observe_removed)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "at least one callback must be provided");
  }

  auto observer = g_slice_new (GumV8ModuleObserver);
  observer->ref_count = 1;
  observer->on_added = observe_added
      ? new Global<Function> (isolate, on_added)
      : nullptr;
  observer->on_removed = observe_removed
      ? new Global<Function> (isolate, on_removed)
      : nullptr;
  observer->resource = new Global<Object> (isolate, callback_val.As<Object> ());
  observer->added_handler = 0;
  observer->removed_handler = 0;
  observer->parent = module;

  {
    ScriptUnlocker unlocker (core);

    auto registry = gum_module_registry_obtain ();

    gum_module_registry_lock (registry);

    if (observe_added)
    {
      observer->added_handler = g_signal_connect_data (registry,
          "module-added",
          G_CALLBACK (gum_emit_added_module),
          gum_v8_module_observer_ref (observer),
          (GClosureNotify) gum_v8_module_observer_unref,
          (GConnectFlags) 0);
    }

    if (observe_removed)
    {
      observer->removed_handler = g_signal_connect_data (registry,
          "module-removed",
          G_CALLBACK (gum_emit_removed_module),
          gum_v8_module_observer_ref (observer),
          (GClosureNotify) gum_v8_module_observer_unref,
          (GConnectFlags) 0);
    }

    if (observe_added)
    {
      gum_module_registry_enumerate_modules (registry,
          (GumFoundModuleFunc) gum_emit_existing_module, observer);
    }

    gum_module_registry_unlock (registry);
  }

  auto observer_template_value (Local<Object>::New (isolate,
      *module->module_observer_value));
  auto observer_value (observer_template_value->Clone ());
  observer_value->SetAlignedPointerInInternalField (0, observer);

  g_hash_table_add (module->module_observers, observer);

  info.GetReturnValue ().Set (observer_value);
}

static GumV8ModuleObserver *
gum_v8_module_observer_ref (GumV8ModuleObserver * observer)
{
  g_atomic_int_inc (&observer->ref_count);

  return observer;
}

static void
gum_v8_module_observer_unref (GumV8ModuleObserver * observer)
{
  if (!g_atomic_int_dec_and_test (&observer->ref_count))
    return;

  {
    ScriptScope scope (observer->parent->core->script);

    delete observer->on_added;
    delete observer->on_removed;
    delete observer->resource;
  }

  g_slice_free (GumV8ModuleObserver, observer);
}

static void
gum_v8_module_observer_destroy (GumV8ModuleObserver * self)
{
  auto registry = gum_module_registry_obtain ();

  gulong * handlers[] = {
    &self->added_handler,
    &self->removed_handler,
  };
  for (guint i = 0; i != G_N_ELEMENTS (handlers); i++)
  {
    gulong * handler = handlers[i];

    if (*handler != 0)
    {
      g_signal_handler_disconnect (registry, *handler);
      *handler = 0;
    }
  }

  gum_v8_module_observer_unref (self);
}

static void
gum_v8_process_detach_module_observer (GumV8Process * self,
                                       GumV8ModuleObserver * observer)
{
  g_hash_table_remove (self->module_observers, observer);
}

static gboolean
gum_emit_existing_module (GumModule * module,
                          GumV8ModuleObserver * observer)
{
  gum_v8_module_observer_invoke (observer, observer->on_added, module);

  return TRUE;
}

static void
gum_emit_added_module (GumModuleRegistry * registry,
                       GumModule * module,
                       GumV8ModuleObserver * observer)
{
  gum_v8_module_observer_invoke (observer, observer->on_added, module);
}

static void
gum_emit_removed_module (GumModuleRegistry * registry,
                         GumModule * module,
                         GumV8ModuleObserver * observer)
{
  gum_v8_module_observer_invoke (observer, observer->on_removed, module);
}

static void
gum_v8_module_observer_invoke (GumV8ModuleObserver * self,
                               Global<Function> * callback,
                               GumModule * module)
{
  auto parent = self->parent;
  auto core = parent->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  Local<Value> wrapper =
      _gum_v8_module_new_from_handle (module, parent->module);

  auto callback_value = Local<Function>::New (isolate, *callback);
  Local<Value> result;
  _gum_v8_ignore_result (callback_value->Call (isolate->GetCurrentContext (),
        Undefined (isolate), 1, &wrapper).ToLocal (&result));
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
  handler->callback = new Global<Function> (core->isolate, callback);
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

  _gum_v8_cpu_context_free_later (new Global<Object> (isolate, context), core);

  return handled;
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_observer_detach,
                           GumV8ModuleObserver)
{
  if (self != NULL)
  {
    wrapper->SetAlignedPointerInInternalField (0, NULL);

    gum_v8_process_detach_module_observer (module, self);
  }
}
