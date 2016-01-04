/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

struct _GumDukExceptionHandler
{
  GumDukHeapPtr callback;
  GumDukCore * core;
};

struct _GumDukMatchContext
{
  GumDukProcess * self;
  GumDukHeapPtr on_match;
  GumDukHeapPtr on_complete;
  duk_context * ctx;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_process_construct)
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

static GumDukExceptionHandler * gum_duk_exception_handler_new (
    GumDukHeapPtr callback, GumDukCore * core);
static void gum_duk_exception_handler_free (
    GumDukExceptionHandler * handler);
static gboolean gum_duk_exception_handler_on_exception (
    GumExceptionDetails * details, gpointer user_data);

static const duk_function_list_entry gumjs_process_functions[] =
{
  { "isDebuggerAttached", gumjs_process_is_debugger_attached, 0},
  { "getCurrentThreadId", gumjs_process_get_current_thread_id, 0},
  { "enumerateThreads", gumjs_process_enumerate_threads, 1 },
  { "enumerateModules", gumjs_process_enumerate_modules, 1 },
  { "_enumerateRanges", gumjs_process_enumerate_ranges, 2 },
  { "enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges, 1 },
  { "setExceptionHandler", gumjs_process_set_exception_handler, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_process_init (GumDukProcess * self,
                       GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_process_construct, 0);
  // [ newobj ]
  duk_push_object (ctx);
  // [ newobj newproto ]
  duk_put_function_list (ctx, -1, gumjs_process_functions);
  duk_push_string (ctx, GUM_SCRIPT_ARCH);
  // [ newobj newproto arch ]
  duk_put_prop_string (ctx, -2, "arch");
  // [ newobj newproto ]
  duk_push_string (ctx, GUM_SCRIPT_PLATFORM);
  // [ newobj newproto platform ]
  duk_put_prop_string (ctx, -2, "platform");
  // [ newobj newproto ]
  duk_push_uint (ctx, gum_query_page_size ());
  // [ newobj newproto pagesize ]
  duk_put_prop_string (ctx, -2, "pageSize");
  // [ newobj newproto ]
  duk_push_uint (ctx, GLIB_SIZEOF_VOID_P);
  // [ newobj newproto ptrsize ]
  duk_put_prop_string (ctx, -2, "pointerSize");
  // [ newobj newproto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ newobj ]
  duk_new (ctx, 0);
  // [ newinst ]
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Process");
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
   return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  duk_push_boolean (ctx,
      gum_process_is_debugger_attached () ? TRUE : FALSE);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  duk_push_number (ctx, gum_process_get_current_thread_id ());
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }
  mc.ctx = ctx;

  gum_process_enumerate_threads (gum_emit_thread, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  int res = duk_pcall (ctx, 0);
  if (res)
  {
    printf ("Error when performing on_complete\n");
  }
  /* TODO: add any exceptions to the scope. */
  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukCore * core = mc->self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  GumDukHeapPtr thread, context;
  const gchar * result;
  gboolean proceed;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (core->backend),
      details->id))
    return TRUE;

  duk_push_object (ctx);
  // [ newobj ]
  duk_push_uint (ctx, details->id);
  // [ newobj id ]
  duk_put_prop_string (ctx, -2, "id");
  // [ newobj ]
  duk_push_string (ctx, _gumjs_thread_state_to_string (details->state));
  // [ newobj state ]
  duk_put_prop_string (ctx, -2, "state");
  context = _gumjs_cpu_context_new (ctx,
      (GumCpuContext *) &details->cpu_context, GUM_CPU_CONTEXT_READONLY, core);
  duk_push_heapptr (ctx, context);
  // [ newobj context ]
  duk_put_prop_string (ctx, -2, "context");
  // [ newobj ]

  thread = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  duk_push_heapptr (ctx, mc->on_match);
  duk_push_heapptr (ctx, thread);
  int res = duk_pcall (ctx, 1);
  if (res)
  {
    duk_get_prop_string (ctx, -1, "stack");
    printf ("error occurred while performing on_match: %s\n%s\n",
        duk_safe_to_string (ctx, -2), duk_safe_to_string (ctx, -1));
    duk_pop (ctx);
    /* TODO: add any exceptions to the scope. */
  }
  result = duk_safe_to_string (ctx, -1);

  proceed = strcmp (result, "stop") != 0;

  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
  {
    duk_push_null (ctx);
    return 1;
  }
  mc.ctx = ctx;

  gum_process_enumerate_modules (gum_emit_module, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_pcall (ctx, 0);
  /* TODO: add any exceptions to the scope. */
  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukCore * core = mc->self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  GumDukHeapPtr module, pointer;
  const gchar * result;
  gint res;
  gboolean proceed;

  duk_push_object (ctx);
  // [ newobj ]
  duk_push_string (ctx, details->name);
  // [ newobj name ]
  duk_put_prop_string (ctx, -2, "name");
  // [ newobj ]
  pointer = _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (details->range->base_address), core);
  duk_push_heapptr (ctx, pointer);
  _gumjs_duk_release_heapptr (ctx, pointer);
  // [ newobj baseaddr ]
  duk_put_prop_string (ctx, -2, "base");
  // [ newobj ]
  duk_push_uint (ctx, details->range->size);
  // [ newobj size ]
  duk_put_prop_string (ctx, -2, "size");
  // [ newobj ]
  duk_push_string (ctx, details->path);
  // [ newobj path ]
  duk_put_prop_string (ctx, -2, "path");
  // [ newobj ]

  module = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  duk_push_heapptr (ctx, mc->on_match);
  duk_push_heapptr (ctx, module);
  res = duk_pcall (ctx, 1);
  if (res)
     printf ("error occured when running on_match\n");
  /* TODO: add any exceptions to the scope. */
  result = duk_safe_to_string (ctx, -1);

  proceed = strcmp (result, "stop") != 0;

  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumDukMatchContext mc;
  GumPageProtection prot;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
  {
     duk_push_null (ctx);
     return 1;
  }
  mc.ctx = ctx;

  gum_process_enumerate_ranges (prot, gum_emit_range, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_pcall (ctx, 0);
  /* TODO: add any exceptions to the scope. */
  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukCore * core = mc->self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  char prot_str[4] = "---";
  GumDukHeapPtr range, pointer;
  const GumFileMapping * f = details->file;
  const gchar * result;
  gboolean proceed;

  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  duk_push_object (ctx);
  // [ newobj ]
  pointer = _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (details->range->base_address), core);
  duk_push_heapptr (ctx, pointer);
  _gumjs_duk_release_heapptr (ctx, pointer);
  // [ newobj baseaddr ]
  duk_put_prop_string (ctx, -2, "base");
  // [ newobj ]
  duk_push_uint (ctx, details->range->size);
  // [ newobj size ]
  duk_put_prop_string (ctx, -2, "size");
  // [ newobj ]
  duk_push_string (ctx, prot_str);
  // [ newobj prot_str ]
  duk_put_prop_string (ctx, -2, "protection");
  // [ newobj ]

  range = _gumjs_duk_require_heapptr (ctx, -1);

  if (f != NULL)
  {
    duk_push_object (ctx);
    // [ newobj newfileobj ]
    duk_push_string (ctx, f->path);
    // [ newobj newfileobj path ]
    duk_put_prop_string (ctx, -2, "path");
    // [ newobj newfileobj ]
    duk_push_uint (ctx, f->offset);
    // [ newobj newfileobj offset ]
    duk_put_prop_string (ctx, -2, "offset");
    // [ newobj newfileobj ]
    duk_put_prop_string (ctx, -2, "file");
    // [ newobj ]
  }
  duk_pop (ctx);
  // []

  duk_push_heapptr (ctx, mc->on_match);
  // [ on_match ]
  duk_push_heapptr (ctx, range);
  // [ on_match range ]
  duk_pcall (ctx, 1);
  /* TODO: add exception data to scope */

  result = duk_safe_to_string (ctx, -1);
  proceed = strcmp (result, "stop") != 0;

  duk_pop (ctx);
  _gumjs_duk_release_heapptr (ctx, range);

  _gum_duk_scope_flush (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
#ifdef HAVE_DARWIN
  GumDukMatchContext mc;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (args->core);

  mc.self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  if (!_gumjs_args_parse (ctx, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
  {
     duk_push_null (ctx);
     return 1;
  }
  mc.ctx = ctx;

  gum_process_enumerate_malloc_ranges (gum_emit_malloc_range, &mc);

  duk_push_heapptr (ctx, mc.on_complete);
  duk_pcall (ctx, 0);
  /* TODO: add exception data to scope */
  duk_pop (ctx);

  _gum_duk_scope_flush (&scope);

  duk_push_undefined (ctx);
  return 1;
#else
  _gumjs_throw (ctx, "not implemented yet for " GUM_SCRIPT_PLATFORM);
  duk_push_null (ctx);
  return 1;
#endif
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       gpointer user_data)
{
  GumDukMatchContext * mc = user_data;
  GumDukCore * core = mc->self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = mc->ctx;
  GumDukHeapPtr range, pointer;
  const gchar * result;
  gboolean proceed;

  duk_push_object (ctx);
  // [ newobj ]
  pointer = _gumjs_native_pointer_new (ctx,
      GSIZE_TO_POINTER (details->range->base_address), core);
  duk_push_heapptr (ctx, pointer);
  _gumjs_duk_release_heapptr (ctx, pointer);
  // [ newobj base ]
  duk_put_prop_string (ctx, -2, "base");
  // [ newobj ]
  duk_push_uint (ctx, details->range->size);
  // [ newobj size ]
  duk_put_prop_string (ctx, -2, "size");
  // [ newobj ]
  range = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  duk_push_heapptr (ctx, mc->on_match);
  // [ on_match ]
  duk_push_heapptr (ctx, range);
  // [ on_match range ]
  duk_pcall (ctx, 1);
  // [ result ]
  /* TODO: add exception data to scope */

  result = duk_safe_to_string (ctx, -1);
  proceed = strcmp (result, "stop") != 0;
  _gumjs_duk_release_heapptr (ctx, range);

  _gum_duk_scope_flush (&scope);

  duk_pop (ctx);
  // []

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumDukProcess * self;
  GumDukCore * core;
  GumDukHeapPtr callback;
  GumDukExceptionHandler * new_handler, * old_handler;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  core = self->core;

  if (!_gumjs_args_parse (ctx, "F?", &callback))
  {
    duk_push_null (ctx);
    return 1;
  }

  new_handler = (callback != NULL)
      ? gum_duk_exception_handler_new (callback, core)
      : NULL;

  old_handler = self->exception_handler;
  self->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_duk_exception_handler_free (old_handler);

  duk_push_undefined (ctx);
  return 1;
}

static GumDukExceptionHandler *
gum_duk_exception_handler_new (GumDukHeapPtr callback,
                               GumDukCore * core)
{
  GumDukExceptionHandler * handler;

  handler = g_slice_new (GumDukExceptionHandler);
  _gumjs_duk_protect (core->ctx, callback);
  handler->callback = callback;
  handler->core = core;

  gum_exceptor_add (core->exceptor, gum_duk_exception_handler_on_exception,
      handler);

  return handler;
}

static void
gum_duk_exception_handler_free (GumDukExceptionHandler * handler)
{
  gum_exceptor_remove (handler->core->exceptor,
      gum_duk_exception_handler_on_exception, handler);

  _gumjs_duk_unprotect (handler->core->ctx, handler->callback);

  g_slice_free (GumDukExceptionHandler, handler);
}

static gboolean
gum_duk_exception_handler_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumDukExceptionHandler * handler = user_data;
  GumDukCore * core = handler->core;
  GumDukScope scope;
  duk_context * ctx = core->ctx;
  GumDukHeapPtr exception, cpu_context;
  GumDukValue * result;
  gboolean handled;

  printf ("in gum_duk_exception_handler_on_exception\n");
  _gum_duk_scope_enter (&scope, core);

  _gumjs_parse_exception_details (ctx, details, core, &exception, &cpu_context);

  duk_push_heapptr (ctx, handler->callback);
  // [ callback ]
  duk_push_heapptr (ctx, exception);
  // [ callback exception ]
  _gumjs_duk_release_heapptr (ctx, exception);
  int res = duk_pcall (ctx, 1);
  if (res)
    printf ("pcall failed\n");
  // [ result ]
  /* TODO: add exception data to scope */
  result = _gumjs_get_value (ctx, -1);

  _gumjs_cpu_context_detach (ctx, cpu_context);

  handled = FALSE;
  if (result != NULL)
  {
    if (result->type == DUK_TYPE_BOOLEAN)
      handled = result->data._boolean;
    g_free (result);
  }

  duk_pop (ctx);
  // []
  _gum_duk_scope_leave (&scope);

  return handled;
}
