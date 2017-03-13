/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukprocess.h"

#include "gumdukmacros.h"

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
#elif defined (G_OS_WIN32)
# define GUM_SCRIPT_PLATFORM "windows"
#elif defined (HAVE_QNX)
# define GUM_SCRIPT_PLATFORM "qnx"
#endif

typedef struct _GumDukMatchContext GumDukMatchContext;
typedef struct _GumDukFindRangeByAddressContext GumDukFindRangeByAddressContext;

struct _GumDukExceptionHandler
{
  GumDukHeapPtr callback;
  GumDukCore * core;
};

struct _GumDukMatchContext
{
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;

  GumDukScope * scope;
};

struct _GumDukFindRangeByAddressContext
{
  GumAddress address;

  GumDukCore * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_process_construct)
GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_range_by_address)
static gboolean gum_push_range_if_containing_address (
    const GumRangeDetails * details, GumDukFindRangeByAddressContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumDukMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumDukExceptionHandler * gum_duk_exception_handler_new (
    GumDukHeapPtr callback, GumDukCore * core);
static void gum_duk_exception_handler_free (
    GumDukExceptionHandler * handler);
static gboolean gum_duk_exception_handler_on_exception (
    GumExceptionDetails * details, GumDukExceptionHandler * handler);

static const duk_function_list_entry gumjs_process_functions[] =
{
  { "isDebuggerAttached", gumjs_process_is_debugger_attached, 0 },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id, 0 },
  { "enumerateThreads", gumjs_process_enumerate_threads, 1 },
  { "enumerateModules", gumjs_process_enumerate_modules, 1 },
  { "findRangeByAddress", gumjs_process_find_range_by_address, 1 },
  { "_enumerateRanges", gumjs_process_enumerate_ranges, 2 },
  { "enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges, 1 },
  { "setExceptionHandler", gumjs_process_set_exception_handler, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_process_init (GumDukProcess * self,
                       GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_process_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_process_functions);
  duk_push_string (ctx, GUM_SCRIPT_ARCH);
  duk_put_prop_string (ctx, -2, "arch");
  duk_push_string (ctx, GUM_SCRIPT_PLATFORM);
  duk_put_prop_string (ctx, -2, "platform");
  duk_push_uint (ctx, gum_query_page_size ());
  duk_put_prop_string (ctx, -2, "pageSize");
  duk_push_uint (ctx, GLIB_SIZEOF_VOID_P);
  duk_put_prop_string (ctx, -2, "pointerSize");
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "Process");
}

void
_gum_duk_process_flush (GumDukProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_duk_exception_handler_free);
}

void
_gum_duk_process_dispose (GumDukProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_duk_exception_handler_free);
}

void
_gum_duk_process_finalize (GumDukProcess * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_process_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  (void) args;

  duk_push_boolean (ctx,
      gum_process_is_debugger_attached () ? TRUE : FALSE);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  (void) args;

  duk_push_number (ctx, gum_process_get_current_thread_id ());
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);
  duk_push_uint (ctx, details->id);
  duk_put_prop_string (ctx, -2, "id");
  duk_push_string (ctx, _gum_duk_thread_state_to_string (details->state));
  duk_put_prop_string (ctx, -2, "state");
  _gum_duk_push_cpu_context (ctx, (GumCpuContext *) &details->cpu_context,
      GUM_CPU_CONTEXT_READONLY, scope->core);
  duk_put_prop_string (ctx, -2, "context");

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  duk_push_string (ctx, details->name);
  duk_put_prop_string (ctx, -2, "name");

  _gum_duk_push_native_pointer (ctx,
      GSIZE_TO_POINTER (details->range->base_address), scope->core);
  duk_put_prop_string (ctx, -2, "base");

  duk_push_uint (ctx, details->range->size);
  duk_put_prop_string (ctx, -2, "size");

  duk_push_string (ctx, details->path);
  duk_put_prop_string (ctx, -2, "path");

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_range_by_address)
{
  GumDukFindRangeByAddressContext fc;
  gpointer ptr;

  _gum_duk_args_parse (args, "p", &ptr);

  fc.address = GUM_ADDRESS (ptr);
  fc.core = args->core;

  duk_push_null (ctx);

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS,
      (GumFoundRangeFunc) gum_push_range_if_containing_address, &fc);

  return 1;
}

static gboolean
gum_push_range_if_containing_address (const GumRangeDetails * details,
                                      GumDukFindRangeByAddressContext * fc)
{
  gboolean proceed = TRUE;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, fc->address))
  {
    GumDukScope scope = GUM_DUK_SCOPE_INIT (fc->core);
    duk_context * ctx = scope.ctx;

    duk_pop (ctx);
    _gum_duk_push_range (ctx, details, fc->core);

    proceed = FALSE;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumDukMatchContext mc;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);
  _gum_duk_push_range (ctx, details, scope->core);

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

#ifdef HAVE_DARWIN

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumDukMatchContext * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  _gum_duk_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete);
  mc.scope = &scope;

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);
  _gum_duk_scope_flush (&scope);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_call (ctx, 0);
  duk_pop (ctx);

  return 0;
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumDukMatchContext * mc)
{
  GumDukScope * scope = mc->scope;
  duk_context * ctx = scope->ctx;
  gboolean proceed = TRUE;

  duk_push_heapptr (ctx, mc->on_match);

  duk_push_object (ctx);

  _gum_duk_push_native_pointer (ctx,
      GSIZE_TO_POINTER (details->range->base_address), scope->core);
  duk_put_prop_string (ctx, -2, "base");

  duk_push_uint (ctx, details->range->size);
  duk_put_prop_string (ctx, -2, "size");

  if (_gum_duk_scope_call_sync (scope, 1))
  {
    if (duk_is_string (ctx, -1))
      proceed = strcmp (duk_require_string (ctx, -1), "stop") != 0;
  }
  else
  {
    proceed = FALSE;
  }
  duk_pop (ctx);

  return proceed;
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  (void) args;

  _gum_duk_throw (ctx, "not yet implemented for " GUM_SCRIPT_PLATFORM);
  return 0;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumDukProcess * self;
  GumDukHeapPtr callback;
  GumDukExceptionHandler * new_handler, * old_handler;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  _gum_duk_args_parse (args, "F?", &callback);

  new_handler = (callback != NULL)
      ? gum_duk_exception_handler_new (callback, self->core)
      : NULL;

  old_handler = self->exception_handler;
  self->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_duk_exception_handler_free (old_handler);

  return 0;
}

static GumDukExceptionHandler *
gum_duk_exception_handler_new (GumDukHeapPtr callback,
                               GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  GumDukExceptionHandler * handler;

  handler = g_slice_new (GumDukExceptionHandler);
  _gum_duk_protect (scope.ctx, callback);
  handler->callback = callback;
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_duk_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_duk_exception_handler_free (GumDukExceptionHandler * handler)
{
  GumDukCore * core = handler->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);

  gum_exceptor_remove (core->exceptor,
      (GumExceptionHandler) gum_duk_exception_handler_on_exception, handler);

  _gum_duk_unprotect (scope.ctx, handler->callback);

  g_slice_free (GumDukExceptionHandler, handler);
}

static gboolean
gum_duk_exception_handler_on_exception (GumExceptionDetails * details,
                                        GumDukExceptionHandler * handler)
{
  GumDukCore * core = handler->core;
  GumDukScope scope;
  duk_context * ctx;
  GumDukCpuContext * cpu_context;
  gboolean handled = FALSE;

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_push_exception_details (ctx, details, core, &cpu_context);

  duk_push_heapptr (ctx, handler->callback);
  duk_dup (ctx, -2);
  if (_gum_duk_scope_call (&scope, 1))
  {
    if (duk_is_boolean (ctx, -1))
      handled = duk_require_boolean (ctx, -1);
  }

  _gum_duk_cpu_context_make_read_only (cpu_context);

  duk_pop_2 (ctx);

  _gum_duk_scope_leave (&scope);

  return handled;
}
