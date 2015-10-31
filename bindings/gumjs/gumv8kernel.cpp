/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8kernel.h"

#include <gum/gumkernel.h>
#include <string.h>

using namespace v8;

typedef struct _GumV8MatchContext GumV8MatchContext;

struct _GumV8MatchContext
{
  GumV8Kernel * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static void gum_v8_kernel_on_enumerate_threads (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_script_handle_thread_match (
    const GumThreadDetails * details, gpointer user_data);

static void gum_v8_script_kmemory_on_read_byte_array (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_script_kmemory_on_write_byte_array (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_script_kmemory_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_script_kmemory_handle_range_match (
    const GumRangeDetails * details, gpointer user_data);

void
_gum_v8_kernel_init (GumV8Kernel * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> kernel = ObjectTemplate::New (isolate);
  kernel->Set (String::NewFromUtf8 (isolate, "enumerateThreads"),
      FunctionTemplate::New (isolate, gum_v8_kernel_on_enumerate_threads,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Kernel"), kernel);

  Handle<ObjectTemplate> memory = ObjectTemplate::New (isolate);
  memory->Set (String::NewFromUtf8 (isolate, "readByteArray"),
      FunctionTemplate::New (isolate, gum_v8_script_kmemory_on_read_byte_array,
      data));
  memory->Set (String::NewFromUtf8 (isolate, "writeByteArray"),
      FunctionTemplate::New (isolate, gum_v8_script_kmemory_on_write_byte_array,
      data));
  memory->Set (String::NewFromUtf8 (isolate, "_enumerateRanges"),
      FunctionTemplate::New (isolate, gum_v8_script_kmemory_on_enumerate_ranges,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Memory"), memory);
}

void
_gum_v8_kernel_realize (GumV8Kernel * self)
{
  (void) self;
}

void
_gum_v8_kernel_dispose (GumV8Kernel * self)
{
  (void) self;
}

void
_gum_v8_kernel_finalize (GumV8Kernel * self)
{
  (void) self;
}

/*
 * Prototype:
 * Kernel.enumerateThreads(callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_kernel_on_enumerate_threads (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8MatchContext ctx;

  ctx.self = static_cast<GumV8Kernel *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  Local<Value> callbacks_value = info[0];
  if (!callbacks_value->IsObject ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "Kernel.enumerateThreads: argument must be "
        "a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_v8_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_v8_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  ctx.receiver = info.This ();

  gum_kernel_enumerate_threads (gum_v8_script_handle_thread_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_v8_script_handle_thread_match (const GumThreadDetails * details,
                                   gpointer user_data)
{
  GumV8MatchContext * ctx =
      static_cast<GumV8MatchContext *> (user_data);
  GumV8Core * core = ctx->self->core;
  Isolate * isolate = ctx->isolate;

  Local<Object> thread (Object::New (isolate));
  _gum_v8_object_set (thread, "id", Number::New (isolate, details->id), core);
  _gum_v8_object_set (thread, "state", String::NewFromOneByte (isolate,
      (const uint8_t *) _gum_v8_thread_state_to_string (details->state)),
      core);
  Local<Object> cpu_context =
      _gum_v8_cpu_context_new (&details->cpu_context, ctx->self->core);
  _gum_v8_object_set (thread, "context", cpu_context, core);

  Handle<Value> argv[] = { thread };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, cpu_context),
      core);

  return proceed;
}

/*
 * Prototype:
 * Memory.readByteArray(address, length)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_script_kmemory_on_read_byte_array (const FunctionCallbackInfo<Value> & info)
{
  GumV8Kernel * self = static_cast<GumV8Kernel *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected address and length")));
    return;
  }

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, self->core))
  {
    return;
  }
  else if (address == NULL)
  {
    info.GetReturnValue ().Set (Null (isolate));
    return;
  }

  int64_t size = info[1]->IntegerValue ();

  Local<Value> result;
  if (size > 0)
  {
    gsize n_bytes_read;
    guint8 * data = gum_kernel_read (GUM_ADDRESS (address), size,
        &n_bytes_read);
    if (data != NULL)
    {
      result = ArrayBuffer::New (isolate, data, n_bytes_read,
          ArrayBufferCreationMode::kInternalized);
    }
    else
    {
      gchar * message = g_strdup_printf (
          "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (address));
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
          message)));
      g_free (message);
      return;
    }
  }
  else
  {
    result = Array::New (isolate, 0);
  }

  info.GetReturnValue ().Set (result);
}

/*
 * Prototype:
 * Memory.writeByteArray(address, bytes)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_script_kmemory_on_write_byte_array (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Kernel * self = static_cast<GumV8Kernel *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected address and data")));
    return;
  }

  gpointer address;
  if (!_gum_v8_native_pointer_get (info[0], &address, self->core))
    return;

  GBytes * bytes = _gum_v8_byte_array_get (info[1], self->core);
  if (bytes == NULL)
    return;

  gsize size;
  guint8 * data = (guint8 *) g_bytes_get_data (bytes, &size);

  if (!gum_kernel_write (GUM_ADDRESS (address), data, size))
  {
    gchar * message = g_strdup_printf (
        "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (address));
    isolate->ThrowException (Exception::Error (String::NewFromUtf8 (isolate,
        message)));
    g_free (message);
  }
}

/*
 * Prototype:
 * Memory._enumerateRanges(prot, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_script_kmemory_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8MatchContext ctx;

  ctx.self = static_cast<GumV8Kernel *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  GumPageProtection prot;
  if (!_gum_v8_page_protection_get (info[0], &prot, ctx.self->core))
    return;

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    ctx.isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        ctx.isolate, "Memory.enumerateRanges: second argument must be "
        "a callback object")));
    return;
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_v8_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_v8_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  ctx.receiver = info.This ();

  gum_kernel_enumerate_ranges (prot, gum_v8_script_kmemory_handle_range_match,
      &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);
}

static gboolean
gum_v8_script_kmemory_handle_range_match (const GumRangeDetails * details,
                                          gpointer user_data)
{
  GumV8MatchContext * ctx =
      static_cast<GumV8MatchContext *> (user_data);
  GumV8Core * core = ctx->self->core;
  Isolate * isolate = ctx->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Local<Object> range (Object::New (isolate));
  _gum_v8_object_set_pointer (range, "base", details->range->base_address, core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_ascii (range, "protection", prot_str, core);

  const GumFileMapping * f = details->file;
  if (f != NULL)
  {
    Local<Object> file (Object::New (isolate));
    _gum_v8_object_set_utf8 (range, "path", f->path, core);
    _gum_v8_object_set_uint (range, "offset", f->offset, core);
    _gum_v8_object_set (range, "file", file, core);
  }

  Handle<Value> argv[] = {
    range
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

