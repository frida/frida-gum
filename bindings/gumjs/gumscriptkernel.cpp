/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptkernel.h"

#include <gum/gumkernel.h>
#include <string.h>

using namespace v8;

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptKernel * self;
  Isolate * isolate;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static void gum_script_kmemory_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_script_kmemory_handle_range_match (
    const GumRangeDetails * details, gpointer user_data);

void
_gum_script_kernel_init (GumScriptKernel * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> memory = ObjectTemplate::New (isolate);
  memory->Set (String::NewFromUtf8 (isolate, "enumerateRanges"),
      FunctionTemplate::New (isolate, gum_script_kmemory_on_enumerate_ranges,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Memory"), memory);
}

void
_gum_script_kernel_realize (GumScriptKernel * self)
{
  (void) self;
}

void
_gum_script_kernel_dispose (GumScriptKernel * self)
{
  (void) self;
}

void
_gum_script_kernel_finalize (GumScriptKernel * self)
{
  (void) self;
}

/*
 * Prototype:
 * Memory.enumerateRanges(prot, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_kmemory_on_enumerate_ranges (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptKernel *> (
      info.Data ().As<External> ()->Value ());
  ctx.isolate = info.GetIsolate ();

  GumPageProtection prot;
  if (!_gum_script_page_protection_get (info[0], &prot, ctx.self->core))
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
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match,
      ctx.self->core))
  {
    return;
  }
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete,
      ctx.self->core))
  {
    return;
  }

  ctx.receiver = info.This ();

  gum_kernel_enumerate_ranges (prot, gum_script_kmemory_handle_range_match,
      &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return;
}

static gboolean
gum_script_kmemory_handle_range_match (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);
  GumScriptCore * core = ctx->self->core;
  Isolate * isolate = ctx->isolate;

  char prot_str[4] = "---";
  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Local<Object> range (Object::New (isolate));
  _gum_script_set_pointer (range, "base", details->range->base_address, core);
  _gum_script_set_uint (range, "size", details->range->size, core);
  _gum_script_set_ascii (range, "protection", prot_str, core);

  const GumFileMapping * f = details->file;
  if (f != NULL)
  {
    Local<Object> file (Object::New (isolate));
    _gum_script_set_utf8 (range, "path", f->path, core);
    _gum_script_set_uint (range, "offset", f->offset, core);
    _gum_script_set (range, "file", file, core);
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

