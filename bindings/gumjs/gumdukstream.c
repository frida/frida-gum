/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukstream.h"

#include "gumdukmacros.h"

#ifdef G_OS_WIN32
# include <gio/gwin32inputstream.h>
# include <gio/gwin32outputstream.h>

# define GUM_NATIVE_INPUT_STREAM "Win32InputStream"
# define GUM_NATIVE_OUTPUT_STREAM "Win32OutputStream"
# define GUM_NATIVE_KIND "Windows file handle"
typedef gpointer GumStreamHandle;
#else
# include <gio/gunixinputstream.h>
# include <gio/gunixoutputstream.h>

# define GUM_NATIVE_INPUT_STREAM "UnixInputStream"
# define GUM_NATIVE_OUTPUT_STREAM "UnixOutputStream"
# define GUM_NATIVE_KIND "file descriptor"
typedef gint GumStreamHandle;
#endif

typedef struct _GumDukCloseIOStreamOperation GumDukCloseIOStreamOperation;

typedef struct _GumDukCloseInputOperation GumDukCloseInputOperation;
typedef struct _GumDukReadOperation GumDukReadOperation;
typedef guint GumDukReadStrategy;

typedef struct _GumDukCloseOutputOperation GumDukCloseOutputOperation;
typedef struct _GumDukWriteOperation GumDukWriteOperation;
typedef guint GumDukWriteStrategy;

struct _GumDukCloseIOStreamOperation
{
  GIOStream * stream;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukStream * module;
};

struct _GumDukCloseInputOperation
{
  GInputStream * stream;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukStream * module;
};

struct _GumDukReadOperation
{
  GInputStream * stream;
  GumDukReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukStream * module;
};

enum _GumDukReadStrategy
{
  GUM_DUK_READ_SOME,
  GUM_DUK_READ_ALL
};

struct _GumDukCloseOutputOperation
{
  GOutputStream * stream;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukStream * module;
};

struct _GumDukWriteOperation
{
  GOutputStream * stream;
  GumDukWriteStrategy strategy;
  GBytes * bytes;
  GumDukHeapPtr callback;
  GumScriptJob * job;

  GumDukStream * module;
};

enum _GumDukWriteStrategy
{
  GUM_DUK_WRITE_SOME,
  GUM_DUK_WRITE_ALL
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_io_stream_construct)
GUMJS_DECLARE_FINALIZER (gumjs_io_stream_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_io_stream_close)
static void gum_duk_close_io_stream_operation_free (
    GumDukCloseIOStreamOperation * op);
static void gum_duk_close_io_stream_operation_start (
    GumDukCloseIOStreamOperation * self);
static void gum_duk_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumDukCloseIOStreamOperation * self);

static void gum_duk_push_input_stream (duk_context * ctx, GInputStream * stream,
    GumDukStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_input_stream_construct)
GUMJS_DECLARE_FINALIZER (gumjs_input_stream_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_close)
static void gum_duk_close_input_operation_free (GumDukCloseInputOperation * op);
static void gum_duk_close_input_operation_start (
    GumDukCloseInputOperation * self);
static void gum_duk_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumDukCloseInputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read_all)
static gint gumjs_input_stream_read_with_strategy (duk_context * ctx,
    const GumDukArgs * args, GumDukReadStrategy strategy);
static void gum_duk_read_operation_free (GumDukReadOperation * op);
static void gum_duk_read_operation_start (GumDukReadOperation * self);
static void gum_duk_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumDukReadOperation * self);

static void gum_duk_push_output_stream (duk_context * ctx,
    GOutputStream * stream, GumDukStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_output_stream_construct)
GUMJS_DECLARE_FINALIZER (gumjs_output_stream_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_close)
static void gum_duk_close_output_operation_free (
    GumDukCloseOutputOperation * op);
static void gum_duk_close_output_operation_start (
    GumDukCloseOutputOperation * self);
static void gum_duk_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumDukCloseOutputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_all)
static gint gumjs_output_stream_write_with_strategy (duk_context * ctx,
    const GumDukArgs * args, GumDukWriteStrategy strategy);
static void gum_duk_write_operation_free (GumDukWriteOperation * op);
static void gum_duk_write_operation_start (GumDukWriteOperation * self);
static void gum_duk_write_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumDukWriteOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_input_stream_construct)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_output_stream_construct)

static void gum_duk_native_stream_ctor_args_parse (const GumDukArgs * args,
    GumStreamHandle * handle, gboolean * auto_close);

static const duk_function_list_entry gumjs_io_stream_functions[] =
{
  { "_close", gumjs_io_stream_close, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_input_stream_functions[] =
{
  { "_close", gumjs_input_stream_close, 1 },
  { "_read", gumjs_input_stream_read, 2 },
  { "_readAll", gumjs_input_stream_read_all, 2 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_output_stream_functions[] =
{
  { "_close", gumjs_output_stream_close, 1 },
  { "_write", gumjs_output_stream_write, 2 },
  { "_writeAll", gumjs_output_stream_write_all, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_stream_init (GumDukStream * self,
                      GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "stream", self);

  duk_push_c_function (ctx, gumjs_io_stream_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_io_stream_functions);
  duk_push_c_function (ctx, gumjs_io_stream_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->io_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "IOStream");

  duk_push_c_function (ctx, gumjs_input_stream_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_input_stream_functions);
  duk_push_c_function (ctx, gumjs_input_stream_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->input_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InputStream");

  duk_push_c_function (ctx, gumjs_output_stream_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_output_stream_functions);
  duk_push_c_function (ctx, gumjs_output_stream_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->output_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "OutputStream");

  _gum_duk_create_subclass (ctx, "InputStream", GUM_NATIVE_INPUT_STREAM,
      gumjs_native_input_stream_construct, 2, NULL);

  _gum_duk_create_subclass (ctx, "OutputStream", GUM_NATIVE_OUTPUT_STREAM,
      gumjs_native_output_stream_construct, 2, NULL);

  self->cancellable = g_cancellable_new ();
}

void
_gum_duk_stream_flush (GumDukStream * self)
{
  g_cancellable_cancel (self->cancellable);
}

void
_gum_duk_stream_dispose (GumDukStream * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  _gum_duk_release_heapptr (ctx, self->io_stream);
  _gum_duk_release_heapptr (ctx, self->input_stream);
  _gum_duk_release_heapptr (ctx, self->output_stream);
}

void
_gum_duk_stream_finalize (GumDukStream * self)
{
  g_clear_object (&self->cancellable);
}

static GumDukStream *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "stream");
}

static gpointer
gumjs_stream_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  gpointer stream;

  duk_push_this (ctx);
  stream = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return stream;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_io_stream_construct)
{
  GIOStream * stream;
  GumDukStream * module;

  stream = G_IO_STREAM (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);

  gum_duk_push_input_stream (ctx,
      g_object_ref (g_io_stream_get_input_stream (stream)), module);
  duk_put_prop_string (ctx, -2, "input");

  gum_duk_push_output_stream (ctx,
      g_object_ref (g_io_stream_get_output_stream (stream)), module);
  duk_put_prop_string (ctx, -2, "output");

  _gum_duk_put_data (ctx, -1, stream);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_io_stream_finalize)
{
  GIOStream * stream;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "IOStream"))
    return 0;

  stream = _gum_duk_steal_data (ctx, 0);
  if (stream == NULL)
    return 0;

  g_object_unref (stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_io_stream_close)
{
  GIOStream * stream;
  GumDukStream * module;
  GumDukCore * core;
  GumDukHeapPtr callback;
  GumDukCloseIOStreamOperation * op;

  stream = gumjs_stream_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "F", &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukCloseIOStreamOperation);
  op->stream = g_object_ref (stream);
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_close_io_stream_operation_start, op,
      (GDestroyNotify) gum_duk_close_io_stream_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_close_io_stream_operation_free (GumDukCloseIOStreamOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_object_unref (op->stream);

  g_slice_free (GumDukCloseIOStreamOperation, op);
}

static void
gum_duk_close_io_stream_operation_start (GumDukCloseIOStreamOperation * self)
{
  g_io_stream_close_async (self->stream, G_PRIORITY_DEFAULT,
      self->module->cancellable,
      (GAsyncReadyCallback) gum_duk_close_io_stream_operation_finish, self);
}

static void
gum_duk_close_io_stream_operation_finish (GIOStream * stream,
                                          GAsyncResult * result,
                                          GumDukCloseIOStreamOperation * self)
{
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_io_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  duk_push_boolean (ctx, success);
  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

static void
gum_duk_push_input_stream (duk_context * ctx,
                           GInputStream * stream,
                           GumDukStream * module)
{
  duk_push_heapptr (ctx, module->input_stream);
  duk_push_pointer (ctx, stream);
  duk_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_input_stream_construct)
{
  GInputStream * stream;

  stream = G_INPUT_STREAM (duk_require_pointer (ctx, 0));

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, stream);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_input_stream_finalize)
{
  GInputStream * stream;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "InputStream"))
    return 0;

  stream = _gum_duk_steal_data (ctx, 0);
  if (stream == NULL)
    return 0;

  g_object_unref (stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_close)
{
  GInputStream * stream;
  GumDukStream * module;
  GumDukCore * core;
  GumDukHeapPtr callback;
  GumDukCloseInputOperation * op;

  stream = gumjs_stream_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "F", &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukCloseInputOperation);
  op->stream = g_object_ref (stream);
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_close_input_operation_start, op,
      (GDestroyNotify) gum_duk_close_input_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_close_input_operation_free (GumDukCloseInputOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_object_unref (op->stream);

  g_slice_free (GumDukCloseInputOperation, op);
}

static void
gum_duk_close_input_operation_start (GumDukCloseInputOperation * self)
{
  g_input_stream_close_async (self->stream, G_PRIORITY_DEFAULT,
      self->module->cancellable,
      (GAsyncReadyCallback) gum_duk_close_input_operation_finish, self);
}

static void
gum_duk_close_input_operation_finish (GInputStream * stream,
                                      GAsyncResult * result,
                                      GumDukCloseInputOperation * self)
{
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_input_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  duk_push_boolean (ctx, success);
  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read)
{
  return gumjs_input_stream_read_with_strategy (ctx, args, GUM_DUK_READ_SOME);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read_all)
{
  return gumjs_input_stream_read_with_strategy (ctx, args, GUM_DUK_READ_ALL);
}

static gint
gumjs_input_stream_read_with_strategy (duk_context * ctx,
                                       const GumDukArgs * args,
                                       GumDukReadStrategy strategy)
{
  GInputStream * stream;
  GumDukStream * module;
  GumDukCore * core;
  guint64 size;
  GumDukHeapPtr callback;
  GumDukReadOperation * op;

  stream = gumjs_stream_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "QF", &size, &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukReadOperation);
  op->stream = g_object_ref (stream);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_read_operation_start, op,
      (GDestroyNotify) gum_duk_read_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_read_operation_free (GumDukReadOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_free (op->buffer);
  g_object_unref (op->stream);

  g_slice_free (GumDukReadOperation, op);
}

static void
gum_duk_read_operation_start (GumDukReadOperation * self)
{
  if (self->strategy == GUM_DUK_READ_SOME)
  {
    g_input_stream_read_async (self->stream, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_duk_read_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_DUK_READ_ALL);

    g_input_stream_read_all_async (self->stream, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_duk_read_operation_finish, self);
  }
}

static void
gum_duk_read_operation_finish (GInputStream * stream,
                               GAsyncResult * result,
                               GumDukReadOperation * self)
{
  gsize bytes_read = 0;
  GError * error = NULL;
  GumDukScope scope;
  duk_context * ctx;
  gboolean emit_data;

  if (self->strategy == GUM_DUK_READ_SOME)
  {
    gsize n;

    n = g_input_stream_read_finish (stream, result, &error);
    if (n > 0)
      bytes_read = n;
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_DUK_READ_ALL);

    g_input_stream_read_all_finish (stream, result, &bytes_read, &error);
  }

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);

  if (self->strategy == GUM_DUK_READ_ALL && bytes_read != self->buffer_size)
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s",
        (error != NULL) ? error->message : "Short read");
    emit_data = TRUE;
  }
  else if (error == NULL)
  {
    duk_push_null (ctx);
    emit_data = TRUE;
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    emit_data = FALSE;
  }

  g_clear_error (&error);

  if (emit_data)
  {
    if (bytes_read > 0)
    {
      gpointer buffer_data;

      buffer_data = duk_push_fixed_buffer (ctx, bytes_read);
      memcpy (buffer_data, self->buffer, bytes_read);
    }
    else
    {
      duk_push_fixed_buffer (ctx, 0);
    }

    duk_push_buffer_object (ctx, -1, 0, bytes_read, DUK_BUFOBJ_ARRAYBUFFER);
    duk_swap (ctx, -2, -1);
    duk_pop (ctx);
  }
  else
  {
    duk_push_null (ctx);
  }

  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

static void
gum_duk_push_output_stream (duk_context * ctx,
                            GOutputStream * stream,
                            GumDukStream * module)
{
  duk_push_heapptr (ctx, module->output_stream);
  duk_push_pointer (ctx, stream);
  duk_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_output_stream_construct)
{
  GOutputStream * stream;

  stream = G_OUTPUT_STREAM (duk_require_pointer (ctx, 0));

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, stream);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_output_stream_finalize)
{
  GOutputStream * stream;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "OutputStream"))
    return 0;

  stream = _gum_duk_steal_data (ctx, 0);
  if (stream == NULL)
    return 0;

  g_object_unref (stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_close)
{
  GInputStream * stream;
  GumDukStream * module;
  GumDukCore * core;
  GumDukHeapPtr callback;
  GumDukCloseOutputOperation * op;

  stream = gumjs_stream_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "F", &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukCloseOutputOperation);
  op->stream = g_object_ref (stream);
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_close_output_operation_start, op,
      (GDestroyNotify) gum_duk_close_output_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_close_output_operation_free (GumDukCloseOutputOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_object_unref (op->stream);

  g_slice_free (GumDukCloseOutputOperation, op);
}

static void
gum_duk_close_output_operation_start (GumDukCloseOutputOperation * self)
{
  g_output_stream_close_async (self->stream, G_PRIORITY_DEFAULT,
      self->module->cancellable,
      (GAsyncReadyCallback) gum_duk_close_output_operation_finish, self);
}

static void
gum_duk_close_output_operation_finish (GOutputStream * stream,
                                       GAsyncResult * result,
                                       GumDukCloseOutputOperation * self)
{
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_output_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);
  if (error == NULL)
  {
    duk_push_null (ctx);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  duk_push_boolean (ctx, success);
  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write)
{
  return gumjs_output_stream_write_with_strategy (ctx, args,
      GUM_DUK_WRITE_SOME);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write_all)
{
  return gumjs_output_stream_write_with_strategy (ctx, args,
      GUM_DUK_WRITE_ALL);
}

static gint
gumjs_output_stream_write_with_strategy (duk_context * ctx,
                                         const GumDukArgs * args,
                                         GumDukWriteStrategy strategy)
{
  GInputStream * stream;
  GumDukStream * module;
  GumDukCore * core;
  GBytes * bytes;
  GumDukHeapPtr callback;
  GumDukWriteOperation * op;

  stream = gumjs_stream_from_args (args);
  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "BF", &bytes, &callback);

  duk_push_heapptr (ctx, callback);

  op = g_slice_new (GumDukWriteOperation);
  op->stream = g_object_ref (stream);
  op->strategy = strategy;
  op->bytes = bytes;
  op->callback = _gum_duk_require_heapptr (ctx, -1);
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_duk_write_operation_start, op,
      (GDestroyNotify) gum_duk_write_operation_free);

  op->module = module;

  _gum_duk_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);

  duk_pop (ctx);

  return 0;
}

static void
gum_duk_write_operation_free (GumDukWriteOperation * op)
{
  GumDukCore * core = op->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_release_heapptr (ctx, op->callback);
  _gum_duk_scope_leave (&scope);

  g_bytes_unref (op->bytes);
  g_object_unref (op->stream);

  g_slice_free (GumDukWriteOperation, op);
}

static void
gum_duk_write_operation_start (GumDukWriteOperation * self)
{
  if (self->strategy == GUM_DUK_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (self->stream, self->bytes,
        G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_duk_write_operation_finish, self);
  }
  else
  {
    gsize size;
    gconstpointer data;

    g_assert_cmpuint (self->strategy, ==, GUM_DUK_WRITE_ALL);

    data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (self->stream, data, size,
        G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_duk_write_operation_finish, self);
  }
}

static void
gum_duk_write_operation_finish (GOutputStream * stream,
                                GAsyncResult * result,
                                GumDukWriteOperation * self)
{
  gsize bytes_written = 0;
  GError * error = NULL;
  GumDukScope scope;
  duk_context * ctx;

  if (self->strategy == GUM_DUK_WRITE_SOME)
  {
    gssize n;

    n = g_output_stream_write_bytes_finish (stream, result, &error);
    if (n > 0)
      bytes_written = n;
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_DUK_WRITE_ALL);

    g_output_stream_write_all_finish (stream, result, &bytes_written, &error);
  }

  ctx = _gum_duk_scope_enter (&scope, self->module->core);

  duk_push_heapptr (ctx, self->callback);

  if (self->strategy == GUM_DUK_WRITE_ALL &&
      bytes_written != g_bytes_get_size (self->bytes))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s",
        (error != NULL) ? error->message : "Short write");
  }
  else if (error == NULL)
  {
    duk_push_null (ctx);
  }
  else
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
  }

  g_clear_error (&error);

  duk_push_uint (ctx, bytes_written);

  _gum_duk_scope_call (&scope, 2);
  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);

  gum_script_job_free (self->job);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_input_stream_construct)
{
  GumStreamHandle handle;
  gboolean auto_close;
  GInputStream * stream;
  GumDukStream * module;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new " GUM_NATIVE_INPUT_STREAM "()` to create a new instance");
    duk_throw (ctx);
  }

  gum_duk_native_stream_ctor_args_parse (args, &handle, &auto_close);

#ifdef G_OS_WIN32
  stream = g_win32_input_stream_new (handle, auto_close);
#else
  stream = g_unix_input_stream_new (handle, auto_close);
#endif

  module = gumjs_module_from_args (args);

  duk_push_heapptr (ctx, module->input_stream);
  duk_push_this (ctx);
  duk_push_pointer (ctx, stream);
  duk_call_method (ctx, 1);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_output_stream_construct)
{
  GumStreamHandle handle;
  gboolean auto_close;
  GOutputStream * stream;
  GumDukStream * module;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new " GUM_NATIVE_OUTPUT_STREAM "()` to create a new instance");
    duk_throw (ctx);
  }

  gum_duk_native_stream_ctor_args_parse (args, &handle, &auto_close);

#ifdef G_OS_WIN32
  stream = g_win32_output_stream_new (handle, auto_close);
#else
  stream = g_unix_output_stream_new (handle, auto_close);
#endif

  module = gumjs_module_from_args (args);

  duk_push_heapptr (ctx, module->output_stream);
  duk_push_this (ctx);
  duk_push_pointer (ctx, stream);
  duk_call_method (ctx, 1);
  duk_pop (ctx);

  return 0;
}

static void
gum_duk_native_stream_ctor_args_parse (const GumDukArgs * args,
                                       GumStreamHandle * handle,
                                       gboolean * auto_close)
{
  GumDukHeapPtr options = NULL;

#ifdef G_OS_WIN32
  _gum_duk_args_parse (args, "p|O", handle, &options);
#else
  _gum_duk_args_parse (args, "i|O", handle, &options);
#endif

  *auto_close = FALSE;
  if (options != NULL)
  {
    duk_context * ctx = args->ctx;

    duk_push_heapptr (ctx, options);
    duk_get_prop_string (ctx, -1, "autoClose");
    *auto_close = duk_to_boolean (ctx, -1);
    duk_pop_2 (ctx);
  }
}
