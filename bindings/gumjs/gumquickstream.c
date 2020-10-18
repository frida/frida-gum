/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickstream.h"

#include "gumquickmacros.h"

#ifdef HAVE_WINDOWS
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

typedef struct _GumQuickCloseIOStreamOperation GumQuickCloseIOStreamOperation;

typedef struct _GumQuickCloseInputOperation GumQuickCloseInputOperation;
typedef struct _GumQuickReadOperation GumQuickReadOperation;
typedef guint GumQuickReadStrategy;

typedef struct _GumQuickCloseOutputOperation GumQuickCloseOutputOperation;
typedef struct _GumQuickWriteOperation GumQuickWriteOperation;
typedef guint GumQuickWriteStrategy;

struct _GumQuickCloseIOStreamOperation
{
  GumQuickObjectOperation parent;
};

struct _GumQuickCloseInputOperation
{
  GumQuickObjectOperation parent;
};

struct _GumQuickReadOperation
{
  GumQuickObjectOperation parent;
  GumQuickReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
};

enum _GumQuickReadStrategy
{
  GUM_QUICK_READ_SOME,
  GUM_QUICK_READ_ALL
};

struct _GumQuickCloseOutputOperation
{
  GumQuickObjectOperation parent;
};

struct _GumQuickWriteOperation
{
  GumQuickObjectOperation parent;
  GumQuickWriteStrategy strategy;
  GBytes * bytes;
};

enum _GumQuickWriteStrategy
{
  GUM_QUICK_WRITE_SOME,
  GUM_QUICK_WRITE_ALL
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_io_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_io_stream_close)
static void gum_quick_close_io_stream_operation_start (
    GumQuickCloseIOStreamOperation * self);
static void gum_quick_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumQuickCloseIOStreamOperation * self);

static void gum_quick_push_input_stream (JSContext * ctx, GInputStream * stream,
    GumQuickStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_input_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_close)
static void gum_quick_close_input_operation_start (
    GumQuickCloseInputOperation * self);
static void gum_quick_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumQuickCloseInputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read)
GUMJS_DECLARE_FUNCTION (gumjs_input_stream_read_all)
static gint gumjs_input_stream_read_with_strategy (JSContext * ctx,
    const GumQuickArgs * args, GumQuickReadStrategy strategy);
static void gum_quick_read_operation_dispose (GumQuickReadOperation * self);
static void gum_quick_read_operation_start (GumQuickReadOperation * self);
static void gum_quick_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumQuickReadOperation * self);

static void gum_quick_push_output_stream (JSContext * ctx,
    GOutputStream * stream, GumQuickStream * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_output_stream_construct)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_close)
static void gum_quick_close_output_operation_start (
    GumQuickCloseOutputOperation * self);
static void gum_quick_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumQuickCloseOutputOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_all)
GUMJS_DECLARE_FUNCTION (gumjs_output_stream_write_memory_region)
static gint gumjs_output_stream_write_with_strategy (JSContext * ctx,
    const GumQuickArgs * args, GumQuickWriteStrategy strategy);
static void gum_quick_write_operation_dispose (GumQuickWriteOperation * self);
static void gum_quick_write_operation_start (GumQuickWriteOperation * self);
static void gum_quick_write_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumQuickWriteOperation * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_input_stream_construct)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_output_stream_construct)

static void gum_quick_native_stream_ctor_args_parse (const GumQuickArgs * args,
    GumStreamHandle * handle, gboolean * auto_close);

static const JSClassDef gumjs_io_stream_def =
{
  .class_name = "IOStream",
};

static const JSCFunctionListEntry gumjs_io_stream_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_io_stream_close),
};

static const JSClassDef gumjs_input_stream_def =
{
  .class_name = "InputStream",
};

static const JSCFunctionListEntry gumjs_input_stream_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_input_stream_close),
  JS_CFUNC_DEF ("_read", 0, gumjs_input_stream_read),
  JS_CFUNC_DEF ("_readAll", 0, gumjs_input_stream_read_all),
};

static const JSClassDef gumjs_output_stream_def =
{
  .class_name = "OutputStream",
};

static const JSCFunctionListEntry gumjs_output_stream_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_output_stream_close),
  JS_CFUNC_DEF ("_write", 0, gumjs_output_stream_write),
  JS_CFUNC_DEF ("_writeAll", 0, gumjs_output_stream_write_all),
  JS_CFUNC_DEF ("_writeMemoryRegion", 0,
      gumjs_output_stream_write_memory_region),
};

static const JSClassDef gumjs_native_input_stream_def =
{
  .class_name = GUM_NATIVE_INPUT_STREAM,
};

static const JSClassDef gumjs_native_output_stream_def =
{
  .class_name = GUM_NATIVE_OUTPUT_STREAM,
};

void
_gum_quick_stream_init (GumQuickStream * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor, input_stream_proto, output_stream_proto;

  self->core = core;

  _gum_quick_core_store_module_data (core, "stream", self);

  _gum_quick_create_class (ctx, &gumjs_io_stream_def, core,
      &self->io_stream_class, &proto);
  self->io_stream_proto = JS_DupValue (ctx, proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_io_stream_construct,
      gumjs_io_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_io_stream_entries,
      G_N_ELEMENTS (gumjs_io_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_io_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_input_stream_def, core,
      &self->input_stream_class, &proto);
  input_stream_proto = proto;
  ctor = JS_NewCFunction2 (ctx, gumjs_input_stream_construct,
      gumjs_input_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_input_stream_entries,
      G_N_ELEMENTS (gumjs_input_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_input_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_output_stream_def, core,
      &self->output_stream_class, &proto);
  output_stream_proto = proto;
  ctor = JS_NewCFunction2 (ctx, gumjs_output_stream_construct,
      gumjs_output_stream_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_output_stream_entries,
      G_N_ELEMENTS (gumjs_output_stream_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_output_stream_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_native_input_stream_def,
      self->input_stream_class, input_stream_proto, core,
      &self->native_input_stream_class, &proto);

  _gum_quick_create_subclass (ctx, &gumjs_native_output_stream_def,
      self->output_stream_class, output_stream_proto, core,
      &self->native_output_stream_class, &proto);

  _gum_quick_object_manager_init (&self->objects, self, core);
}

void
_gum_quick_stream_flush (GumQuickStream * self)
{
  _gum_quick_object_manager_flush (&self->objects);
}

void
_gum_quick_stream_dispose (GumQuickStream * self)
{
  JSContext * ctx = self->core->ctx;

  _gum_quick_object_manager_free (&self->objects);

  JS_FreeValue (ctx, self->io_stream_proto);
}

void
_gum_quick_stream_finalize (GumQuickStream * self)
{
}

static GumQuickStream *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "stream");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_io_stream_construct)
{
  GIOStream * stream;
  GumQuickStream * module;

  stream = G_IO_STREAM (quick_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  quick_push_this (ctx);
  _gum_quick_object_manager_add (&module->objects, ctx, -1, stream);

  gum_quick_push_input_stream (ctx,
      g_object_ref (g_io_stream_get_input_stream (stream)), module);
  quick_put_prop_string (ctx, -2, "input");

  gum_quick_push_output_stream (ctx,
      g_object_ref (g_io_stream_get_output_stream (stream)), module);
  quick_put_prop_string (ctx, -2, "output");

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_io_stream_close)
{
  GumQuickObject * self, * input, * output;
  GumQuickStream * module;
  JSValue callback;
  GumQuickCloseIOStreamOperation * op;
  GPtrArray * dependencies;

  self = _gum_quick_object_get (args);
  module = self->module;

  _gum_quick_args_parse (args, "F", &callback);

  op = _gum_quick_object_operation_new (GumQuickCloseIOStreamOperation, self,
      callback, gum_quick_close_io_stream_operation_start, NULL);

  dependencies = g_ptr_array_sized_new (2);

  input = _gum_quick_object_manager_lookup (&module->objects,
      g_io_stream_get_input_stream (self->handle));
  if (input != NULL)
  {
    g_cancellable_cancel (input->cancellable);
    g_ptr_array_add (dependencies, input);
  }

  output = _gum_quick_object_manager_lookup (&module->objects,
      g_io_stream_get_output_stream (self->handle));
  if (output != NULL)
  {
    g_cancellable_cancel (output->cancellable);
    g_ptr_array_add (dependencies, output);
  }

  g_cancellable_cancel (self->cancellable);

  _gum_quick_object_operation_schedule_when_idle (op, dependencies);

  g_ptr_array_unref (dependencies);

  return 0;
}

static void
gum_quick_close_io_stream_operation_start (GumQuickCloseIOStreamOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_io_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_quick_close_io_stream_operation_finish, self);
}

static void
gum_quick_close_io_stream_operation_finish (GIOStream * stream,
                                          GAsyncResult * result,
                                          GumQuickCloseIOStreamOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSContext * ctx;

  success = g_io_stream_close_finish (stream, result, &error);

  ctx = _gum_quick_scope_enter (&scope, op->core);

  quick_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    quick_push_null (ctx);
  }
  else
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  quick_push_boolean (ctx, success);
  _gum_quick_scope_call (&scope, 2);
  quick_pop (ctx);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static void
gum_quick_push_input_stream (JSContext * ctx,
                           GInputStream * stream,
                           GumQuickStream * module)
{
  quick_push_heapptr (ctx, module->input_stream);
  quick_push_pointer (ctx, stream);
  quick_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_input_stream_construct)
{
  GInputStream * stream;
  GumQuickStream * module;

  stream = G_INPUT_STREAM (quick_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  quick_push_this (ctx);
  _gum_quick_object_manager_add (&module->objects, ctx, -1, stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_close)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseInputOperation * op;

  self = _gum_quick_object_get (args);

  _gum_quick_args_parse (args, "F", &callback);

  g_cancellable_cancel (self->cancellable);

  op = _gum_quick_object_operation_new (GumQuickCloseInputOperation, self, callback,
      gum_quick_close_input_operation_start, NULL);
  _gum_quick_object_operation_schedule_when_idle (op, NULL);

  return 0;
}

static void
gum_quick_close_input_operation_start (GumQuickCloseInputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_input_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT,
      NULL, (GAsyncReadyCallback) gum_quick_close_input_operation_finish, self);
}

static void
gum_quick_close_input_operation_finish (GInputStream * stream,
                                      GAsyncResult * result,
                                      GumQuickCloseInputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSContext * ctx;

  success = g_input_stream_close_finish (stream, result, &error);

  ctx = _gum_quick_scope_enter (&scope, op->core);

  quick_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    quick_push_null (ctx);
  }
  else
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  quick_push_boolean (ctx, success);
  _gum_quick_scope_call (&scope, 2);
  quick_pop (ctx);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read)
{
  return gumjs_input_stream_read_with_strategy (ctx, args, GUM_QUICK_READ_SOME);
}

GUMJS_DEFINE_FUNCTION (gumjs_input_stream_read_all)
{
  return gumjs_input_stream_read_with_strategy (ctx, args, GUM_QUICK_READ_ALL);
}

static gint
gumjs_input_stream_read_with_strategy (JSContext * ctx,
                                       const GumQuickArgs * args,
                                       GumQuickReadStrategy strategy)
{
  GumQuickObject * self;
  guint64 size;
  JSValue callback;
  GumQuickReadOperation * op;

  self = _gum_quick_object_get (args);

  _gum_quick_args_parse (args, "QF", &size, &callback);

  op = _gum_quick_object_operation_new (GumQuickReadOperation, self, callback,
      gum_quick_read_operation_start, gum_quick_read_operation_dispose);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  _gum_quick_object_operation_schedule (op);

  return 0;
}

static void
gum_quick_read_operation_dispose (GumQuickReadOperation * self)
{
  g_free (self->buffer);
}

static void
gum_quick_read_operation_start (GumQuickReadOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickObject * stream = op->object;

  if (self->strategy == GUM_QUICK_READ_SOME)
  {
    g_input_stream_read_async (stream->handle, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_read_operation_finish, self);
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_READ_ALL);

    g_input_stream_read_all_async (stream->handle, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_read_operation_finish, self);
  }
}

static void
gum_quick_read_operation_finish (GInputStream * stream,
                               GAsyncResult * result,
                               GumQuickReadOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  gsize bytes_read = 0;
  GError * error = NULL;
  GumQuickScope scope;
  JSContext * ctx;
  gboolean emit_data;

  if (self->strategy == GUM_QUICK_READ_SOME)
  {
    gsize n;

    n = g_input_stream_read_finish (stream, result, &error);
    if (n > 0)
      bytes_read = n;
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_READ_ALL);

    g_input_stream_read_all_finish (stream, result, &bytes_read, &error);
  }

  ctx = _gum_quick_scope_enter (&scope, op->core);

  quick_push_heapptr (ctx, op->callback);

  if (self->strategy == GUM_QUICK_READ_ALL && bytes_read != self->buffer_size)
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s",
        (error != NULL) ? error->message : "Short read");
    emit_data = TRUE;
  }
  else if (error == NULL)
  {
    quick_push_null (ctx);
    emit_data = TRUE;
  }
  else
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s", error->message);
    emit_data = FALSE;
  }

  g_clear_error (&error);

  if (emit_data)
  {
    if (bytes_read > 0)
    {
      gpointer buffer_data;

      buffer_data = quick_push_fixed_buffer (ctx, bytes_read);
      memcpy (buffer_data, self->buffer, bytes_read);
    }
    else
    {
      quick_push_fixed_buffer (ctx, 0);
    }

    quick_push_buffer_object (ctx, -1, 0, bytes_read, QUICK_BUFOBJ_ARRAYBUFFER);
    quick_swap (ctx, -2, -1);
    quick_pop (ctx);
  }
  else
  {
    quick_push_null (ctx);
  }

  _gum_quick_scope_call (&scope, 2);
  quick_pop (ctx);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static void
gum_quick_push_output_stream (JSContext * ctx,
                            GOutputStream * stream,
                            GumQuickStream * module)
{
  quick_push_heapptr (ctx, module->output_stream);
  quick_push_pointer (ctx, stream);
  quick_new (ctx, 1);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_output_stream_construct)
{
  GOutputStream * stream;
  GumQuickStream * module;

  stream = G_OUTPUT_STREAM (quick_require_pointer (ctx, 0));
  module = gumjs_module_from_args (args);

  quick_push_this (ctx);
  _gum_quick_object_manager_add (&module->objects, ctx, -1, stream);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_close)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseOutputOperation * op;

  self = _gum_quick_object_get (args);

  _gum_quick_args_parse (args, "F", &callback);

  g_cancellable_cancel (self->cancellable);

  op = _gum_quick_object_operation_new (GumQuickCloseOutputOperation, self,
      callback, gum_quick_close_output_operation_start, NULL);
  _gum_quick_object_operation_schedule_when_idle (op, NULL);

  return 0;
}

static void
gum_quick_close_output_operation_start (GumQuickCloseOutputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);

  g_output_stream_close_async (op->object->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_quick_close_output_operation_finish, self);
}

static void
gum_quick_close_output_operation_finish (GOutputStream * stream,
                                       GAsyncResult * result,
                                       GumQuickCloseOutputOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSContext * ctx;

  success = g_output_stream_close_finish (stream, result, &error);

  ctx = _gum_quick_scope_enter (&scope, op->core);

  quick_push_heapptr (ctx, op->callback);
  if (error == NULL)
  {
    quick_push_null (ctx);
  }
  else
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s", error->message);
    g_error_free (error);
  }
  quick_push_boolean (ctx, success);
  _gum_quick_scope_call (&scope, 2);
  quick_pop (ctx);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write)
{
  return gumjs_output_stream_write_with_strategy (ctx, args,
      GUM_QUICK_WRITE_SOME);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write_all)
{
  return gumjs_output_stream_write_with_strategy (ctx, args,
      GUM_QUICK_WRITE_ALL);
}

GUMJS_DEFINE_FUNCTION (gumjs_output_stream_write_memory_region)
{
  GumQuickObject * self;
  gconstpointer address;
  gsize length;
  JSValue callback;
  GumQuickWriteOperation * op;

  self = _gum_quick_object_get (args);

  _gum_quick_args_parse (args, "pZF", &address, &length, &callback);

  op = _gum_quick_object_operation_new (GumQuickWriteOperation, self, callback,
      gum_quick_write_operation_start, gum_quick_write_operation_dispose);
  op->strategy = GUM_QUICK_WRITE_ALL;
  op->bytes = g_bytes_new_static (address, length);
  _gum_quick_object_operation_schedule (op);

  return 0;
}

static gint
gumjs_output_stream_write_with_strategy (JSContext * ctx,
                                         const GumQuickArgs * args,
                                         GumQuickWriteStrategy strategy)
{
  GumQuickObject * self;
  GBytes * bytes;
  JSValue callback;
  GumQuickWriteOperation * op;

  self = _gum_quick_object_get (args);

  _gum_quick_args_parse (args, "BF", &bytes, &callback);

  op = _gum_quick_object_operation_new (GumQuickWriteOperation, self, callback,
      gum_quick_write_operation_start, gum_quick_write_operation_dispose);
  op->strategy = strategy;
  op->bytes = bytes;
  _gum_quick_object_operation_schedule (op);

  return 0;
}

static void
gum_quick_write_operation_dispose (GumQuickWriteOperation * self)
{
  g_bytes_unref (self->bytes);
}

static void
gum_quick_write_operation_start (GumQuickWriteOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickObject * stream = op->object;

  if (self->strategy == GUM_QUICK_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (stream->handle, self->bytes,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_write_operation_finish, self);
  }
  else
  {
    gsize size;
    gconstpointer data;

    g_assert (self->strategy == GUM_QUICK_WRITE_ALL);

    data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (stream->handle, data, size,
        G_PRIORITY_DEFAULT, stream->cancellable,
        (GAsyncReadyCallback) gum_quick_write_operation_finish, self);
  }
}

static void
gum_quick_write_operation_finish (GOutputStream * stream,
                                GAsyncResult * result,
                                GumQuickWriteOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  gsize bytes_written = 0;
  GError * error = NULL;
  GumQuickScope scope;
  JSContext * ctx;

  if (self->strategy == GUM_QUICK_WRITE_SOME)
  {
    gssize n;

    n = g_output_stream_write_bytes_finish (stream, result, &error);
    if (n > 0)
      bytes_written = n;
  }
  else
  {
    g_assert (self->strategy == GUM_QUICK_WRITE_ALL);

    g_output_stream_write_all_finish (stream, result, &bytes_written, &error);
  }

  ctx = _gum_quick_scope_enter (&scope, op->core);

  quick_push_heapptr (ctx, op->callback);

  if (self->strategy == GUM_QUICK_WRITE_ALL &&
      bytes_written != g_bytes_get_size (self->bytes))
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s",
        (error != NULL) ? error->message : "Short write");
  }
  else if (error == NULL)
  {
    quick_push_null (ctx);
  }
  else
  {
    quick_push_error_object (ctx, QUICK_ERR_ERROR, "%s", error->message);
  }

  g_clear_error (&error);

  quick_push_uint (ctx, bytes_written);

  _gum_quick_scope_call (&scope, 2);
  quick_pop (ctx);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_input_stream_construct)
{
  GumStreamHandle handle;
  gboolean auto_close;
  GInputStream * stream;
  GumQuickStream * module;

  if (!quick_is_constructor_call (ctx))
  {
    _gum_quick_throw (ctx, "use `new " GUM_NATIVE_INPUT_STREAM "()` to create "
        "a new instance");
  }

  gum_quick_native_stream_ctor_args_parse (args, &handle, &auto_close);

#ifdef HAVE_WINDOWS
  stream = g_win32_input_stream_new (handle, auto_close);
#else
  stream = g_unix_input_stream_new (handle, auto_close);
#endif
  module = gumjs_module_from_args (args);

  quick_push_heapptr (ctx, module->input_stream);
  quick_push_this (ctx);
  quick_push_pointer (ctx, stream);
  quick_call_method (ctx, 1);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_output_stream_construct)
{
  GumStreamHandle handle;
  gboolean auto_close;
  GOutputStream * stream;
  GumQuickStream * module;

  if (!quick_is_constructor_call (ctx))
  {
    _gum_quick_throw (ctx, "use `new " GUM_NATIVE_OUTPUT_STREAM "()` to create "
        "a new instance");
  }

  gum_quick_native_stream_ctor_args_parse (args, &handle, &auto_close);

#ifdef HAVE_WINDOWS
  stream = g_win32_output_stream_new (handle, auto_close);
#else
  stream = g_unix_output_stream_new (handle, auto_close);
#endif
  module = gumjs_module_from_args (args);

  quick_push_heapptr (ctx, module->output_stream);
  quick_push_this (ctx);
  quick_push_pointer (ctx, stream);
  quick_call_method (ctx, 1);

  return 0;
}

static void
gum_quick_native_stream_ctor_args_parse (const GumQuickArgs * args,
                                       GumStreamHandle * handle,
                                       gboolean * auto_close)
{
  JSValue options = JS_NULL;

#ifdef HAVE_WINDOWS
  _gum_quick_args_parse (args, "p|O", handle, &options);
#else
  _gum_quick_args_parse (args, "i|O", handle, &options);
#endif

  *auto_close = FALSE;
  if (options != NULL)
  {
    JSContext * ctx = args->ctx;

    quick_push_heapptr (ctx, options);
    quick_get_prop_string (ctx, -1, "autoClose");
    *auto_close = quick_to_boolean (ctx, -1);
    quick_pop_2 (ctx);
  }
}
