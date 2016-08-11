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

typedef struct _GumV8CloseInputOperation GumV8CloseInputOperation;
typedef struct _GumV8ReadOperation GumV8ReadOperation;
typedef guint GumV8ReadStrategy;

typedef struct _GumV8CloseOutputOperation GumV8CloseOutputOperation;
typedef struct _GumV8WriteOperation GumV8WriteOperation;
typedef guint GumV8WriteStrategy;

struct _GumV8CloseInputOperation
{
  GInputStream * stream;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Stream * module;
};

struct _GumV8ReadOperation
{
  GInputStream * stream;
  GumV8ReadStrategy strategy;
  gpointer buffer;
  gsize buffer_size;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Stream * module;
};

enum _GumV8ReadStrategy
{
  GUM_V8_READ_SOME,
  GUM_V8_READ_ALL
};

struct _GumV8CloseOutputOperation
{
  GOutputStream * stream;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Stream * module;
};

struct _GumV8WriteOperation
{
  GOutputStream * stream;
  GumV8WriteStrategy strategy;
  GBytes * bytes;
  GumPersistent<Function>::type * callback;
  GumScriptJob * job;

  GumV8Stream * module;
};

enum _GumV8WriteStrategy
{
  GUM_V8_WRITE_SOME,
  GUM_V8_WRITE_ALL
};

static void gum_v8_input_stream_on_new (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_input_stream_on_close (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_close_input_operation_free (GumV8CloseInputOperation * op);
static void gum_v8_close_input_operation_start (GumV8CloseInputOperation * self);
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
static void gum_v8_close_output_operation_free (GumV8CloseOutputOperation * op);
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

static gboolean gum_v8_stream_constructor_args_parse (
    const FunctionCallbackInfo<Value> & info, GumStreamHandle * handle,
    gboolean * auto_close, GumV8Core * core);

static void gum_v8_stream_on_weak_notify (
    const WeakCallbackInfo<GumV8Stream> & info);
static void gum_v8_stream_handle_free (gpointer data);

void
_gum_v8_stream_init (GumV8Stream * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Local<FunctionTemplate> input_stream = FunctionTemplate::New (isolate,
      gum_v8_input_stream_on_new, data);
  input_stream->SetClassName (String::NewFromUtf8 (isolate,
      GUM_NATIVE_INPUT_STREAM));
  Local<ObjectTemplate> input_stream_proto = input_stream->PrototypeTemplate ();
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_close, data));
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_read"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_read, data));
  input_stream_proto->Set (String::NewFromUtf8 (isolate, "_readAll"),
      FunctionTemplate::New (isolate, gum_v8_input_stream_on_read_all, data));
  input_stream->InstanceTemplate ()->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, GUM_NATIVE_INPUT_STREAM),
      input_stream);

  Local<FunctionTemplate> output_stream = FunctionTemplate::New (isolate,
      gum_v8_output_stream_on_new, data);
  output_stream->SetClassName (String::NewFromUtf8 (isolate,
      GUM_NATIVE_OUTPUT_STREAM));
  Local<ObjectTemplate> output_stream_proto =
      output_stream->PrototypeTemplate ();
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_close"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_close, data));
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_write"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_write, data));
  output_stream_proto->Set (String::NewFromUtf8 (isolate, "_writeAll"),
      FunctionTemplate::New (isolate, gum_v8_output_stream_on_write_all, data));
  output_stream->InstanceTemplate ()->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, GUM_NATIVE_OUTPUT_STREAM),
      output_stream);

  self->streams = g_hash_table_new_full (NULL, NULL, g_object_unref,
      gum_v8_stream_handle_free);
  self->cancellable = g_cancellable_new ();
}

void
_gum_v8_stream_realize (GumV8Stream * self)
{
  (void) self;
}

void
_gum_v8_stream_flush (GumV8Stream * self)
{
  g_cancellable_cancel (self->cancellable);
}

void
_gum_v8_stream_dispose (GumV8Stream * self)
{
  g_hash_table_remove_all (self->streams);
}

void
_gum_v8_stream_finalize (GumV8Stream * self)
{
  g_clear_object (&self->cancellable);
  g_clear_pointer (&self->streams, g_hash_table_unref);
}

static void
gum_v8_input_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new " GUM_NATIVE_INPUT_STREAM "()` to create a new "
        "instance")));
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_stream_constructor_args_parse (info, &handle, &auto_close, core))
    return;

  GInputStream * stream;
#ifdef G_OS_WIN32
  stream = g_win32_input_stream_new (handle, auto_close);
#else
  stream = g_unix_input_stream_new (handle, auto_close);
#endif

  Local<Object> instance (info.Holder ());
  instance->SetAlignedPointerInInternalField (0, stream);
  instance->SetAlignedPointerInInternalField (1, module);

  GumPersistent<Object>::type * instance_handle =
      new GumPersistent<Object>::type (core->isolate, instance);
  instance_handle->MarkIndependent ();
  instance_handle->SetWeak (module, gum_v8_stream_on_weak_notify,
      WeakCallbackType::kInternalFields);

  g_hash_table_insert (module->streams, stream, instance_handle);
}

static void
gum_v8_input_stream_on_close (
    const FunctionCallbackInfo<Value> & info)
{
  GInputStream * stream = static_cast<GInputStream *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  GumV8CloseInputOperation * op;

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

  op = g_slice_new (GumV8CloseInputOperation);
  op->stream = stream;
  g_object_ref (stream);
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_close_input_operation_start, op,
      (GDestroyNotify) gum_v8_close_input_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_close_input_operation_free (GumV8CloseInputOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_object_unref (op->stream);

  g_slice_free (GumV8CloseInputOperation, op);
}

static void
gum_v8_close_input_operation_start (GumV8CloseInputOperation * self)
{
  g_input_stream_close_async (self->stream, G_PRIORITY_DEFAULT,
      self->module->cancellable,
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
    GumV8Core * core = self->module->core;
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

    gum_script_job_free (self->job);
  }
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
  GInputStream * stream = static_cast<GInputStream *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  GumV8ReadOperation * op;

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected size and callback")));
    return;
  }

  guint64 size;
  if (!_gum_v8_uint64_get (info[0], &size, core))
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

  op = g_slice_new (GumV8ReadOperation);
  op->stream = stream;
  g_object_ref (stream);
  op->strategy = strategy;
  op->buffer = g_malloc (size);
  op->buffer_size = size;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_read_operation_start, op,
      (GDestroyNotify) gum_v8_read_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_read_operation_free (GumV8ReadOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_free (op->buffer);
  g_object_unref (op->stream);

  g_slice_free (GumV8ReadOperation, op);
}

static void
gum_v8_read_operation_start (GumV8ReadOperation * self)
{
  if (self->strategy == GUM_V8_READ_SOME)
  {
    g_input_stream_read_async (self->stream, self->buffer, self->buffer_size,
        G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_v8_read_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_READ_ALL);

    g_input_stream_read_all_async (self->stream, self->buffer,
        self->buffer_size, G_PRIORITY_DEFAULT, self->module->cancellable,
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
    GumV8Core * core = self->module->core;
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

    gum_script_job_free (self->job);
  }
}

static void
gum_v8_output_stream_on_new (const FunctionCallbackInfo<Value> & info)
{
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new " GUM_NATIVE_OUTPUT_STREAM "()` to create a new "
        "instance")));
    return;
  }

  GumStreamHandle handle;
  gboolean auto_close;
  if (!gum_v8_stream_constructor_args_parse (info, &handle, &auto_close, core))
    return;

  GOutputStream * stream;
#ifdef G_OS_WIN32
  stream = g_win32_output_stream_new (handle, auto_close);
#else
  stream = g_unix_output_stream_new (handle, auto_close);
#endif

  Local<Object> instance (info.Holder ());
  instance->SetAlignedPointerInInternalField (0, stream);
  instance->SetAlignedPointerInInternalField (1, module);

  GumPersistent<Object>::type * instance_handle =
      new GumPersistent<Object>::type (core->isolate, instance);
  instance_handle->MarkIndependent ();
  instance_handle->SetWeak (module, gum_v8_stream_on_weak_notify,
      WeakCallbackType::kInternalFields);

  g_hash_table_insert (module->streams, stream, instance_handle);
}

static void
gum_v8_output_stream_on_close (
    const FunctionCallbackInfo<Value> & info)
{
  GOutputStream * stream = static_cast<GOutputStream *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  GumV8CloseOutputOperation * op;

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

  op = g_slice_new (GumV8CloseOutputOperation);
  op->stream = stream;
  g_object_ref (stream);
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_close_output_operation_start, op,
      (GDestroyNotify) gum_v8_close_output_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_close_output_operation_free (GumV8CloseOutputOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_object_unref (op->stream);

  g_slice_free (GumV8CloseOutputOperation, op);
}

static void
gum_v8_close_output_operation_start (GumV8CloseOutputOperation * self)
{
  g_output_stream_close_async (self->stream, G_PRIORITY_DEFAULT,
      self->module->cancellable,
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
    GumV8Core * core = self->module->core;
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

    gum_script_job_free (self->job);
  }
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
  GOutputStream * stream = static_cast<GOutputStream *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  GumV8Stream * module = static_cast<GumV8Stream *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = module->core;
  Isolate * isolate = info.GetIsolate ();
  GumV8WriteOperation * op;

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected data and callback")));
    return;
  }

  GBytes * bytes = _gum_v8_byte_array_get (info[0], core);
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

  op = g_slice_new (GumV8WriteOperation);
  op->stream = stream;
  g_object_ref (stream);
  op->strategy = strategy;
  op->bytes = bytes;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback_value.As<Function> ());
  op->job = gum_script_job_new (core->scheduler,
      (GumScriptJobFunc) gum_v8_write_operation_start, op,
      (GDestroyNotify) gum_v8_write_operation_free);

  op->module = module;

  _gum_v8_core_pin (core);
  gum_script_job_start_on_js_thread (op->job);
}

static void
gum_v8_write_operation_free (GumV8WriteOperation * op)
{
  GumV8Core * core = op->module->core;

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_bytes_unref (op->bytes);
  g_object_unref (op->stream);

  g_slice_free (GumV8WriteOperation, op);
}

static void
gum_v8_write_operation_start (GumV8WriteOperation * self)
{
  if (self->strategy == GUM_V8_WRITE_SOME)
  {
    g_output_stream_write_bytes_async (self->stream, self->bytes,
        G_PRIORITY_DEFAULT, self->module->cancellable,
        (GAsyncReadyCallback) gum_v8_write_operation_finish, self);
  }
  else
  {
    g_assert_cmpuint (self->strategy, ==, GUM_V8_WRITE_ALL);

    gsize size;
    gconstpointer data = g_bytes_get_data (self->bytes, &size);

    g_output_stream_write_all_async (self->stream, data, size,
        G_PRIORITY_DEFAULT, self->module->cancellable,
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
    GumV8Core * core = self->module->core;
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

    gum_script_job_free (self->job);
  }
}

static gboolean
gum_v8_stream_constructor_args_parse (const FunctionCallbackInfo<Value> & info,
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

static void
gum_v8_stream_on_weak_notify (
    const WeakCallbackInfo<GumV8Stream> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  gpointer stream = info.GetInternalField (0);
  GumV8Stream * module = static_cast<GumV8Stream *> (info.GetInternalField (1));
  g_hash_table_remove (module->streams, stream);
}

static void
gum_v8_stream_handle_free (gpointer data)
{
  GumPersistent<Object>::type * instance_handle =
      static_cast<GumPersistent<Object>::type *> (data);
  delete instance_handle;
}
