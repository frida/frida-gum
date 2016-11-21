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
  GumDukObjectOperation parent;
};

struct _GumDukCloseInputOperation
{
  GumDukObjectOperation parent;
};

struct _GumDukReadOperation
{
  GumDukObjectOperation parent;
  GumDukReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
};

enum _GumDukReadStrategy
{
  GUM_DUK_READ_SOME,
  GUM_DUK_READ_ALL
};

struct _GumDukCloseOutputOperation
{
  GumDukObjectOperation parent;
};

struct _GumDukWriteOperation
{
  GumDukObjectOperation parent;
  GumDukWriteStrategy strategy;
  GBytes * bytes;
};

enum _GumDukWriteStrategy
{
  GUM_DUK_WRITE_SOME,
  GUM_DUK_WRITE_ALL
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_io_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_io_stream_close)
static void gum_duk_close_io_stream_operation_start (
    GumDukCloseIOStreamOperation * self);
static void gum_duk_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumDukCloseIOStreamOperation * self);

static void gum_duk_push_input_stream (duk_context * ctx, GInputStream * stream,
    GumDukStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_input_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_close)
static void gum_duk_close_input_operation_start (
    GumDukCloseInputOperation * self);
static void gum_duk_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumDukCloseInputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read_all)
static gint gumjs_input_stream_read_with_strategy (duk_context * ctx,
    const GumDukArgs * args, GumDukReadStrategy strategy);
static void gum_duk_read_operation_dispose (GumDukReadOperation * self);
static void gum_duk_read_operation_start (GumDukReadOperation * self);
static void gum_duk_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumDukReadOperation * self);

static void gum_duk_push_output_stream (duk_context * ctx,
    GOutputStream * stream, GumDukStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_output_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_close)
static void gum_duk_close_output_operation_start (
    GumDukCloseOutputOperation * self);
static void gum_duk_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumDukCloseOutputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_all)
static gint gumjs_output_stream_write_with_strategy (duk_context * ctx,
    const GumDukArgs * args, GumDukWriteStrategy strategy);
static void gum_duk_write_operation_dispose (GumDukWriteOperation * self);
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
  duk_put_prop_string (ctx, -2, "prototype");
  self->io_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "IOStream");

  duk_push_c_function (ctx, gumjs_input_stream_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_input_stream_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->input_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InputStream");

  duk_push_c_function (ctx, gumjs_output_stream_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_output_stream_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  self->output_stream = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "OutputStream");

  _gum_duk_create_subclass (ctx, "InputStream", GUM_NATIVE_INPUT_STREAM,
      gumjs_native_input_stream_construct, 2, NULL);

  _gum_duk_create_subclass (ctx, "OutputStream", GUM_NATIVE_OUTPUT_STREAM,
      gumjs_native_output_stream_construct, 2, NULL);

  _gum_duk_object_manager_init (&self->objects, self, core);
}

void
_gum_duk_stream_flush (GumDukStream * self)
{
  _gum_duk_object_manager_flush (&self->objects);
}

void
_gum_duk_stream_dispose (GumDukStream * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  _gum_duk_object_manager_free (&self->objects);

  _gum_duk_release_heapptr (ctx, self->io_stream);
  _gum_duk_release_heapptr (ctx, self->input_stream);
  _gum_duk_release_heapptr (ctx, self->output_stream);
}

void
_gum_duk_stream_finalize (GumDukStream * self)
{
  (void) self;
}

static GumDukStream *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "stream");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_io_stream_construct)
{
  GIOStream * stream;
  GumDukStream * module;

  stream = G_IO_STREAM (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  _gum_duk_object_manager_add (&module->objects, ctx, -1, stream);

  gum_duk_push_input_stream (ctx,
      g_object_ref (g_io_stream_get_input_stream (stream)), module);
  duk_put_prop_string (ctx, -2, "input");

  gum_duk_push_output_stream (ctx,
      g_object_ref (g_io_stream_get_output_stream (stream)), module);
  duk_put_prop_string (ctx, -2, "output");

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_io_stream_close)
{
  GumDukObject * self, * input, * output;
  GumDukStream * module;
  GumDukHeapPtr callback;
  GumDukCloseIOStreamOperation * op;
  GPtrArray * dependencies;

  (void) ctx;

  self = _gum_duk_object_get (args);
  module = self->module;

  _gum_duk_args_parse (args, "F", &callback);

  op = _gum_duk_object_operation_new (GumDukCloseIOStreamOperation, self,
      callback, gum_duk_close_io_stream_operation_start, NULL);

  dependencies = g_ptr_array_sized_new (2);

  input = _gum_duk_object_manager_lookup (&module->objects,
      g_io_stream_get_input_stream (self->handle));
  if (input != NULL)
  {
    g_cancellable_cancel (input->cancellable);
    g_ptr_array_add (dependencies, input);
  }

  output = _gum_duk_object_manager_lookup (&module->objects,
      g_io_stream_get_output_stream (self->handle));
  if (output != NULL)
  {
    g_cancellable_cancel (output->cancellable);
    g_ptr_array_add (dependencies, output);
  }

  g_cancellable_cancel (self->cancellable);

  _gum_duk_object_operation_schedule_when_idle (op, dependencies);

  g_ptr_array_unref (dependencies);

  return 0;
}

static void
gum_duk_close_io_stream_operation_start (GumDukCloseIOStreamOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);

  g_io_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_duk_close_io_stream_operation_finish, self);
}

static void
gum_duk_close_io_stream_operation_finish (GIOStream * stream,
                                          GAsyncResult * result,
                                          GumDukCloseIOStreamOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_io_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
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

  _gum_duk_object_operation_finish (op);
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
  GumDukStream * module;

  stream = G_INPUT_STREAM (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  _gum_duk_object_manager_add (&module->objects, ctx, -1, stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_close)
{
  GumDukObject * self;
  GumDukHeapPtr callback;
  GumDukCloseInputOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "F", &callback);

  g_cancellable_cancel (self->cancellable);

  op = _gum_duk_object_operation_new (GumDukCloseInputOperation, self, callback,
      gum_duk_close_input_operation_start, NULL);
  _gum_duk_object_operation_schedule_when_idle (op, NULL);

  return 0;
}

static void
gum_duk_close_input_operation_start (GumDukCloseInputOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);

  g_input_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT,
      NULL, (GAsyncReadyCallback) gum_duk_close_input_operation_finish, self);
}

static void
gum_duk_close_input_operation_finish (GInputStream * stream,
                                      GAsyncResult * result,
                                      GumDukCloseInputOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_input_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
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

  _gum_duk_object_operation_finish (op);
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
  GumDukObject * self;
  guint64 size;
  GumDukHeapPtr callback;
  GumDukReadOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "QF", &size, &callback);

  op = _gum_duk_object_operation_new (GumDukReadOperation, self, callback,
      gum_duk_read_operation_start, gum_duk_read_operation_dispose);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  _gum_duk_object_operation_schedule (op);

  return 0;
}

static void
gum_duk_read_operation_dispose (GumDukReadOperation * self)
{
  g_free (self->buffer);
}

static void
gum_duk_read_operation_start (GumDukReadOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GumDukObject * stream = op->object;

  if (self->strategy == GUM_DUK_READ_SOME)
  {
    g_input_stream_read_async (stream->handle, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_duk_read_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_DUK_READ_ALL);

    g_input_stream_read_all_async (stream->handle, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_duk_read_operation_finish, self);
  }
}

static void
gum_duk_read_operation_finish (GInputStream * stream,
                               GAsyncResult * result,
                               GumDukReadOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
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

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);

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

  _gum_duk_object_operation_finish (op);
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
  GumDukStream * module;

  stream = G_OUTPUT_STREAM (duk_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  duk_push_this (ctx);
  _gum_duk_object_manager_add (&module->objects, ctx, -1, stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_close)
{
  GumDukObject * self;
  GumDukHeapPtr callback;
  GumDukCloseOutputOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "F", &callback);

  g_cancellable_cancel (self->cancellable);

  op = _gum_duk_object_operation_new (GumDukCloseOutputOperation, self,
      callback, gum_duk_close_output_operation_start, NULL);
  _gum_duk_object_operation_schedule_when_idle (op, NULL);

  return 0;
}

static void
gum_duk_close_output_operation_start (GumDukCloseOutputOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);

  g_output_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_duk_close_output_operation_finish, self);
}

static void
gum_duk_close_output_operation_finish (GOutputStream * stream,
                                       GAsyncResult * result,
                                       GumDukCloseOutputOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumDukScope scope;
  duk_context * ctx;

  success = g_output_stream_close_finish (stream, result, &error);

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);
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

  _gum_duk_object_operation_finish (op);
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
  GumDukObject * self;
  GBytes * bytes;
  GumDukHeapPtr callback;
  GumDukWriteOperation * op;

  (void) ctx;

  self = _gum_duk_object_get (args);

  _gum_duk_args_parse (args, "BF", &bytes, &callback);

  op = _gum_duk_object_operation_new (GumDukWriteOperation, self, callback,
      gum_duk_write_operation_start, gum_duk_write_operation_dispose);
  op->strategy = strategy;
  op->bytes = bytes;
  _gum_duk_object_operation_schedule (op);

  return 0;
}

static void
gum_duk_write_operation_dispose (GumDukWriteOperation * self)
{
  g_bytes_unref (self->bytes);
}

static void
gum_duk_write_operation_start (GumDukWriteOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GumDukObject * stream = op->object;

  if (self->strategy == GUM_DUK_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (stream->handle, self->bytes,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_duk_write_operation_finish, self);
  }
  else
  {
    gsize size;
    gconstpointer data;

    g_assert_cmpuint (self->strategy, ==, GUM_DUK_WRITE_ALL);

    data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (stream->handle, data, size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_duk_write_operation_finish, self);
  }
}

static void
gum_duk_write_operation_finish (GOutputStream * stream,
                                GAsyncResult * result,
                                GumDukWriteOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
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

  ctx = _gum_duk_scope_enter (&scope, op->core);

  duk_push_heapptr (ctx, op->callback);

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

  _gum_duk_object_operation_finish (op);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_input_stream_construct)
{
  GumStreamHandle handle;
  gboolean auto_close;
  GInputStream * stream;
  GumDukStream * module;

  if (!duk_is_constructor_call (ctx))
  {
    _gum_duk_throw (ctx, "use `new " GUM_NATIVE_INPUT_STREAM "()` to create "
        "a new instance");
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
    _gum_duk_throw (ctx, "use `new " GUM_NATIVE_OUTPUT_STREAM "()` to create "
        "a new instance");
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
