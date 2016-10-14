/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8stream.h"

#include "gumv8scope.h"

using namespace v8;

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

struct GumV8CloseIOStreamOperation
    : public GumV8ObjectOperation<GIOStream, GumV8Stream>
{
};

struct GumV8CloseInputOperation
    : public GumV8ObjectOperation<GInputStream, GumV8Stream>
{
};

enum GumV8ReadStrategy
{
  GUM_V8_READ_SOME,
  GUM_V8_READ_ALL
};

struct GumV8ReadOperation
    : public GumV8ObjectOperation<GInputStream, GumV8Stream>
{
  GumV8ReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
};

struct GumV8CloseOutputOperation
    : public GumV8ObjectOperation<GOutputStream, GumV8Stream>
{
};

enum GumV8WriteStrategy
{
  GUM_V8_WRITE_SOME,
  GUM_V8_WRITE_ALL
};

struct GumV8WriteOperation
    : public GumV8ObjectOperation<GOutputStream, GumV8Stream>
{
  GumV8WriteStrategy strategy;
  GBytes * bytes;
};

static void gum_v8_io_stream_on_new (const FunctionCallbackInfo<Value> & info);
static void gum_v8_io_stream_on_close (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_close_io_stream_operation_start (
    GumV8CloseIOStreamOperation * self);
static void gum_v8_close_io_stream_operation_finish (GIOStream * stream,
    GAsyncResult * result, GumV8CloseIOStreamOperation * self);

static void gum_v8_input_stream_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_input_stream_on_close (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_close_input_operation_start (
    GumV8CloseInputOperation * self);
static void gum_v8_close_input_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumV8CloseInputOperation * self);
static void gum_v8_input_stream_on_read (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_input_stream_on_read_all (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_input_stream_on_read_with_strategy (
    const FunctionCallbackInfo<Value> & info, GumV8ReadStrategy strategy);
static void gum_v8_read_operation_free (GumV8ReadOperation * op);
static void gum_v8_read_operation_start (GumV8ReadOperation * self);
static void gum_v8_read_operation_finish (GInputStream * stream,
    GAsyncResult * result, GumV8ReadOperation * self);

static void gum_v8_output_stream_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_output_stream_on_close (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_close_output_operation_start (
    GumV8CloseOutputOperation * self);
static void gum_v8_close_output_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumV8CloseOutputOperation * self);
static void gum_v8_output_stream_on_write (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_output_stream_on_write_all (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_output_stream_on_write_with_strategy (
    const FunctionCallbackInfo<Value> & info, GumV8WriteStrategy strategy);
static void gum_v8_write_operation_free (GumV8WriteOperation * op);
static void gum_v8_write_operation_start (GumV8WriteOperation * self);
static void gum_v8_write_operation_finish (GOutputStream * stream,
    GAsyncResult * result, GumV8WriteOperation * self);

static void gum_v8_native_input_stream_on_new (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_native_output_stream_on_new (
    const FunctionCallbackInfo<Value> & info);

static gboolean gum_v8_native_stream_ctor_args_parse (
    const FunctionCallbackInfo<Value> & info, GumStreamHandle * handle,
    gboolean * auto_close, GumV8Core * core);

void
_gum_v8_stream_init (GumV8Stream * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Local<FunctionTemplate> io_stream = FunctionTemplate::New (isolate,
      gum_v8_io_stream_on_new, data);
  io_stream->SetClassName (String::NewFromUtf8 (isolate, "IOStream"));
  Local<ObjectTemplate> io_stream_proto = io_stream->PrototypeTemplate ();
  io_stream_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_io_stream_on_close));
  Local<ObjectTemplate> io_stream_object = io_stream->InstanceTemplate ();
  io_stream_object->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "IOStream"), io_stream);
  self->io_stream =
      new GumPersistent<FunctionTemplate>::type (isolate, io_stream);

  Local<FunctionTemplate> input_stream = FunctionTemplate::New (isolate,
      gum_v8_input_stream_on_new, data);
  input_stream->SetClassName (String::NewFromUtf8 (isolate, "InputStream"));
  Local<ObjectTemplate> input_stream_proto = input_stream->PrototypeTemplate ();
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_close));
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_read"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_read));
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_readAll"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_read_all));
  input_stream->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "InputStream"), input_stream);
  self->input_stream =
      new GumPersistent<FunctionTemplate>::type (isolate, input_stream);

  Local<FunctionTemplate> output_stream = FunctionTemplate::New (isolate,
      gum_v8_output_stream_on_new, data);
  output_stream->SetClassName (String::NewFromUtf8 (isolate, "OutputStream"));
  Local<ObjectTemplate> output_stream_proto =
      output_stream->PrototypeTemplate ();
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_close));
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_write"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_write));
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_writeAll"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_write_all));
  output_stream->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "OutputStream"), output_stream);
  self->output_stream =
      new GumPersistent<FunctionTemplate>::type (isolate, output_stream);

  Local<FunctionTemplate> native_input_stream = FunctionTemplate::New (isolate,
      gum_v8_native_input_stream_on_new, data);
  native_input_stream->SetClassName (String::NewFromUtf8 (isolate,
      GUM_NATIVE_INPUT_STREAM));
  native_input_stream->Inherit (input_stream);
  native_input_stream->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, GUM_NATIVE_INPUT_STREAM),
      native_input_stream);

  Local<FunctionTemplate> native_output_stream = FunctionTemplate::New (isolate,
      gum_v8_native_output_stream_on_new, data);
  native_output_stream->SetClassName (String::NewFromUtf8 (isolate,
      GUM_NATIVE_OUTPUT_STREAM));
  native_output_stream->Inherit (output_stream);
  native_output_stream->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, GUM_NATIVE_OUTPUT_STREAM),
      native_output_stream);
}

void
_gum_v8_stream_realize (GumV8Stream * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_stream_flush (GumV8Stream * self)
{
  gum_v8_object_manager_flush (&self->objects);
}

void
_gum_v8_stream_dispose (GumV8Stream * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_stream_finalize (GumV8Stream * self)
{
  delete self->io_stream;
  delete self->input_stream;
  delete self->output_stream;
  self->io_stream = nullptr;
  self->input_stream = nullptr;
  self->output_stream = nullptr;
}

static void
gum_v8_io_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  Local<Context> context = isolate->GetCurrentContext ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a native IOStream handle")));
    return;
  }
  Local<Value> stream_value = info[0];
  if (!stream_value->IsExternal ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid IOStream handle")));
    return;
  }
  GIOStream * stream = G_IO_STREAM (stream_value.As<External> ()->Value ());

  Local<Object> wrapper (info.Holder ());
  gum_v8_object_manager_add (&module->objects, wrapper, stream, module);

  {
    Local<FunctionTemplate> ctor (
        Local<FunctionTemplate>::New (isolate, *module->input_stream));
    Handle<Value> argv[] = {
        External::New (isolate, g_object_ref (
            g_io_stream_get_input_stream (stream)))
    };
    Local<Object> input = ctor->GetFunction ()->NewInstance (context,
        G_N_ELEMENTS (argv), argv).ToLocalChecked ();
    _gum_v8_object_set (wrapper, "input", input, core);
  }

  {
    Local<FunctionTemplate> ctor (
        Local<FunctionTemplate>::New (isolate, *module->output_stream));
    Handle<Value> argv[] = {
        External::New (isolate, g_object_ref (
            g_io_stream_get_output_stream (stream)))
    };
    Local<Object> output = ctor->GetFunction ()->NewInstance (context,
        G_N_ELEMENTS (argv), argv).ToLocalChecked ();
    _gum_v8_object_set (wrapper, "output", output, core);
  }
}

static void
gum_v8_io_stream_on_close (const FunctionCallbackInfo<Value> & info)
{
  GumV8IOStream * self = gum_v8_object_get<GumV8IOStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected callback")));
    return;
  }

  Local<Value> callback_value = info[0];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8ObjectManager * objects = &self->module->objects;
  GIOStream * stream = self->handle;
  gum_v8_object_manager_cancel (objects,
      g_io_stream_get_input_stream (stream));
  gum_v8_object_manager_cancel (objects,
      g_io_stream_get_output_stream (stream));

  g_cancellable_cancel (self->cancellable);

  GumV8CloseIOStreamOperation * op = gum_v8_object_operation_new (self,
      callback_value, gum_v8_close_io_stream_operation_start);
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_close_io_stream_operation_start (GumV8CloseIOStreamOperation * self)
{
  g_io_stream_close_async (self->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_io_stream_operation_finish, self);
}

static void
gum_v8_close_io_stream_operation_finish (GIOStream * stream,
                                         GAsyncResult * result,
                                         GumV8CloseIOStreamOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_io_stream_close_finish (stream, result, &error);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> success_value = success ? True (isolate) : False (isolate);
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
    }

    Handle<Value> argv[] = { error_value, success_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_input_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a native InputStream handle")));
    return;
  }
  Local<Value> stream_value = info[0];
  if (!stream_value->IsExternal ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid stream handle")));
    return;
  }
  GInputStream * stream = G_INPUT_STREAM (
      stream_value.As<External> ()->Value ());

  gum_v8_object_manager_add (&module->objects, info.Holder (), stream, module);
}

static void
gum_v8_input_stream_on_close (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8InputStream * self = gum_v8_object_get<GumV8InputStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected callback")));
    return;
  }

  Local<Value> callback_value = info[0];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  g_cancellable_cancel (self->cancellable);

  GumV8CloseInputOperation * op = gum_v8_object_operation_new (self,
      callback_value, gum_v8_close_input_operation_start);
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_close_input_operation_start (GumV8CloseInputOperation * self)
{
  g_input_stream_close_async (self->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_input_operation_finish, self);
}

static void
gum_v8_close_input_operation_finish (GInputStream * stream,
                                     GAsyncResult * result,
                                     GumV8CloseInputOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_input_stream_close_finish (stream, result, &error);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> success_value = success ? True (isolate) : False (isolate);
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
    }

    Handle<Value> argv[] = { error_value, success_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_input_stream_on_read (
    const FunctionCallbackInfo<Value> & info)
{
  gum_v8_input_stream_on_read_with_strategy (info, GUM_V8_READ_SOME);
}

static void
gum_v8_input_stream_on_read_all (
    const FunctionCallbackInfo<Value> & info)
{
  gum_v8_input_stream_on_read_with_strategy (info, GUM_V8_READ_ALL);
}

static void
gum_v8_input_stream_on_read_with_strategy (
    const FunctionCallbackInfo<Value> & info,
    GumV8ReadStrategy strategy)
{
  GumV8InputStream * self = gum_v8_object_get<GumV8InputStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected size and callback")));
    return;
  }

  guint64 size;
  if (!_gum_v8_uint64_get (info[0], &size, self->core))
    return;
  if (size == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid size")));
    return;
  }

  Local<Value> callback_value = info[1];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8ReadOperation * op = gum_v8_object_operation_new (self, callback_value,
      gum_v8_read_operation_start, gum_v8_read_operation_free);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_read_operation_free (GumV8ReadOperation * op)
{
  g_free (op->buffer);
}

static void
gum_v8_read_operation_start (GumV8ReadOperation * self)
{
  if (self->strategy == GUM_V8_READ_SOME)
  {
    g_input_stream_read_async (self->handle, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, self->cancellable,
        (GAsyncReadyCallback) gum_v8_read_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_READ_ALL);

    g_input_stream_read_all_async (self->handle, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, self->cancellable,
        (GAsyncReadyCallback) gum_v8_read_operation_finish, self);
  }
}

static void
gum_v8_read_operation_finish (GInputStream * stream,
                              GAsyncResult * result,
                              GumV8ReadOperation * self)
{
  gsize bytes_read = 0;
  GError * error = NULL;

  if (self->strategy == GUM_V8_READ_SOME)
  {
    gsize n;

    n = g_input_stream_read_finish (stream, result, &error);
    if (n > 0)
      bytes_read = n;
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_READ_ALL);

    g_input_stream_read_all_finish (stream, result, &bytes_read, &error);
  }

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value, data_value, null_value;
    null_value = Null (isolate);
    if (self->strategy == GUM_V8_READ_ALL && bytes_read != self->buffer_size)
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate,
              (error != NULL) ? error->message : "Short read"));
      data_value = ArrayBuffer::New (isolate, self->buffer, bytes_read,
          ArrayBufferCreationMode::kInternalized);
      self->buffer = NULL; /* steal it */
    }
    else if (error == NULL)
    {
      error_value = null_value;
      data_value = ArrayBuffer::New (isolate, self->buffer, bytes_read,
          ArrayBufferCreationMode::kInternalized);
      self->buffer = NULL; /* steal it */
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      data_value = null_value;
    }

    g_clear_error (&error);

    Handle<Value> argv[] = { error_value, data_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_output_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected a native OutputStream handle")));
    return;
  }
  Local<Value> stream_value = info[0];
  if (!stream_value->IsExternal ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid stream handle")));
    return;
  }
  GOutputStream * stream = G_OUTPUT_STREAM (
      stream_value.As<External> ()->Value ());

  gum_v8_object_manager_add (&module->objects, info.Holder (), stream, module);
}

static void
gum_v8_output_stream_on_close (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8OutputStream * self = gum_v8_object_get<GumV8OutputStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected callback")));
    return;
  }

  Local<Value> callback_value = info[0];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  g_cancellable_cancel (self->cancellable);

  GumV8CloseOutputOperation * op = gum_v8_object_operation_new (self,
      callback_value, gum_v8_close_output_operation_start);
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_close_output_operation_start (GumV8CloseOutputOperation * self)
{
  g_output_stream_close_async (self->handle, G_PRIORITY_DEFAULT, NULL,
      (GAsyncReadyCallback) gum_v8_close_output_operation_finish, self);
}

static void
gum_v8_close_output_operation_finish (GOutputStream * stream,
                                      GAsyncResult * result,
                                      GumV8CloseOutputOperation * self)
{
  GError * error = NULL;
  gboolean success;

  success = g_output_stream_close_finish (stream, result, &error);

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> success_value = success ? True (isolate) : False (isolate);
    Local<Value> null_value = Null (isolate);
    if (error == NULL)
    {
      error_value = null_value;
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
      g_error_free (error);
    }

    Handle<Value> argv[] = { error_value, success_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_output_stream_on_write (
    const FunctionCallbackInfo<Value> & info)
{
  gum_v8_output_stream_on_write_with_strategy (info, GUM_V8_WRITE_SOME);
}

static void
gum_v8_output_stream_on_write_all (
    const FunctionCallbackInfo<Value> & info)
{
  gum_v8_output_stream_on_write_with_strategy (info, GUM_V8_WRITE_ALL);
}

static void
gum_v8_output_stream_on_write_with_strategy (
    const FunctionCallbackInfo<Value> & info,
    GumV8WriteStrategy strategy)
{
  GumV8OutputStream * self = gum_v8_object_get<GumV8OutputStream> (info);
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected data and callback")));
    return;
  }

  GBytes * bytes = _gum_v8_byte_array_get (info[0], self->core);
  if (bytes == NULL)
    return;

  Local<Value> callback_value = info[1];
  if (!callback_value->IsFunction ())
  {
    g_bytes_unref (bytes);

    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid callback")));
    return;
  }

  GumV8WriteOperation * op = gum_v8_object_operation_new (self, callback_value,
      gum_v8_write_operation_start, gum_v8_write_operation_free);
  op->strategy = strategy;
  op->bytes = bytes;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_write_operation_free (GumV8WriteOperation * op)
{
  g_bytes_unref (op->bytes);
}

static void
gum_v8_write_operation_start (GumV8WriteOperation * self)
{
  if (self->strategy == GUM_V8_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (self->handle, self->bytes,
        G_PRIORITY_DEFAULT, self->cancellable,
        (GAsyncReadyCallback) gum_v8_write_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_WRITE_ALL);

    gsize size;
    gconstpointer data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (self->handle, data, size,
        G_PRIORITY_DEFAULT, self->cancellable,
        (GAsyncReadyCallback) gum_v8_write_operation_finish, self);
  }
}

static void
gum_v8_write_operation_finish (GOutputStream * stream,
                               GAsyncResult * result,
                               GumV8WriteOperation * self)
{
  gsize bytes_written = 0;
  GError * error = NULL;

  if (self->strategy == GUM_V8_WRITE_SOME)
  {
    gssize n;

    n = g_output_stream_write_bytes_finish (stream, result, &error);
    if (n > 0)
      bytes_written = n;
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_WRITE_ALL);

    g_output_stream_write_all_finish (stream, result, &bytes_written, &error);
  }

  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Value> error_value;
    Local<Value> size_value = Integer::NewFromUnsigned (isolate, bytes_written);
    Local<Value> null_value = Null (isolate);
    if (self->strategy == GUM_V8_WRITE_ALL &&
        bytes_written != g_bytes_get_size (self->bytes))
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate,
              (error != NULL) ? error->message : "Short write"));
    }
    else if (error == NULL)
    {
      error_value = null_value;
    }
    else
    {
      error_value = Exception::Error (
          String::NewFromUtf8 (isolate, error->message));
    }

    g_clear_error (&error);

    Handle<Value> argv[] = { error_value, size_value };
    Local<Function> callback (Local<Function>::New (isolate, *self->callback));
    callback->Call (null_value, G_N_ELEMENTS (argv), argv);
  }

  gum_v8_object_operation_finish (self);
}

static void
gum_v8_native_input_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  Local<Context> context = isolate->GetCurrentContext ();

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new " GUM_NATIVE_INPUT_STREAM "()` to create a new "
        "instance")));
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_native_stream_ctor_args_parse (info, &handle, &auto_close, core))
    return;

  GInputStream * stream;
#ifdef G_OS_WIN32
  stream = g_win32_input_stream_new (handle, auto_close);
#else
  stream = g_unix_input_stream_new (handle, auto_close);
#endif

  Local<FunctionTemplate> base_ctor (
      Local<FunctionTemplate>::New (isolate, *module->input_stream));
  Handle<Value> argv[] = { External::New (isolate, stream) };
  base_ctor->GetFunction ()->Call (context, info.Holder (), G_N_ELEMENTS (argv),
      argv).ToLocalChecked ();
}

static void
gum_v8_native_output_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  Local<Context> context = isolate->GetCurrentContext ();

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new " GUM_NATIVE_OUTPUT_STREAM "()` to create a new "
        "instance")));
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_native_stream_ctor_args_parse (info, &handle, &auto_close, core))
    return;

  GOutputStream * stream;
#ifdef G_OS_WIN32
  stream = g_win32_output_stream_new (handle, auto_close);
#else
  stream = g_unix_output_stream_new (handle, auto_close);
#endif

  Local<FunctionTemplate> base_ctor (
      Local<FunctionTemplate>::New (isolate, *module->output_stream));
  Handle<Value> argv[] = { External::New (isolate, stream) };
  base_ctor->GetFunction ()->Call (context, info.Holder (), G_N_ELEMENTS (argv),
      argv).ToLocalChecked ();
}

static gboolean
gum_v8_native_stream_ctor_args_parse (const FunctionCallbackInfo<Value> & info,
                                      GumStreamHandle * handle,
                                      gboolean * auto_close,
                                      GumV8Core * core)
{
  Isolate * isolate = info.GetIsolate ();

  gint num_args = info.Length ();
  if (num_args < 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected a " GUM_NATIVE_KIND)));
    return FALSE;
  }

  Local<Value> handle_value = info[0];
#ifdef G_OS_WIN32
  if (!_gum_v8_native_pointer_get (handle_value, handle, core))
    return FALSE;
#else
  (void) core;

  if (!handle_value->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected a " GUM_NATIVE_KIND)));
    return FALSE;
  }
  *handle = static_cast<gint> (handle_value.As<Number> ()->Value ());
#endif

  *auto_close = FALSE;
  if (num_args >= 2)
  {
    Local<Value> options_value = info[1];
    if (!options_value->IsObject ())
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "options argument must be an object")));
      return FALSE;
    }

    Local<Object> options = options_value.As<Object> ();

    Local<String> auto_close_key (String::NewFromOneByte (isolate,
        reinterpret_cast<const uint8_t *> ("autoClose")));
    if (options->Has (auto_close_key))
    {
      *auto_close =
          options->Get (auto_close_key)->ToBoolean ()->BooleanValue ();
    }
  }

  return TRUE;
}
