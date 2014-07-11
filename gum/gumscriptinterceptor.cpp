/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptinterceptor.h"
#include "gumscriptscope.h"

#include "gumbacktracer.h"
#include "gumsymbolutil-priv.h"

#include <stdio.h>
#include <string.h>

#include <errno.h>

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

using namespace v8;

typedef struct _GumScriptAttachEntry GumScriptAttachEntry;
typedef struct _GumScriptReplaceEntry GumScriptReplaceEntry;

struct _GumScriptAttachEntry
{
  GumPersistent<Function>::type * on_enter;
  GumPersistent<Function>::type * on_leave;
};

struct _GumScriptReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumPersistent<Value>::type * replacement;
};

static void gum_script_interceptor_on_attach (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_interceptor_on_detach_all (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_interceptor_detach_all (GumScriptInterceptor * self);
static void gum_script_interceptor_on_replace (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_interceptor_on_revert (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_replace_entry_free (GumScriptReplaceEntry * entry);

static void gum_script_invocation_context_on_get_system_error (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_invocation_context_on_set_system_error (
    Local<String> property, Local<Value> value,
    const PropertyCallbackInfo<void> & info);
static void gum_script_invocation_context_on_get_thread_id (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_invocation_context_on_get_depth (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_invocation_context_on_get_context(
	Local<String> property, const PropertyCallbackInfo<Value> & info);


static void gum_script_invocation_args_on_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_invocation_args_on_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static void gum_script_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info);

void
_gum_script_interceptor_init (GumScriptInterceptor * self,
                              GumScriptCore * core,
                              Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->attach_entries = g_queue_new ();
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_script_replace_entry_free));

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> interceptor = ObjectTemplate::New (isolate);
  interceptor->Set (String::NewFromUtf8 (isolate, "attach"),
      FunctionTemplate::New (isolate, gum_script_interceptor_on_attach,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "detachAll"),
      FunctionTemplate::New (isolate,  gum_script_interceptor_on_detach_all,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "replace"),
      FunctionTemplate::New (isolate,  gum_script_interceptor_on_replace,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "revert"),
      FunctionTemplate::New (isolate,  gum_script_interceptor_on_revert,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Interceptor"), interceptor);

  // initialize the symbol backend for printing stack traces
  _gum_symbol_util_init();
}

void
_gum_script_interceptor_realize (GumScriptInterceptor * self)
{
  Isolate * isolate = self->core->isolate;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> context = ObjectTemplate::New (isolate);
  context->SetInternalFieldCount (2);
  context->SetAccessor (String::NewFromUtf8 (isolate, GUM_SYSTEM_ERROR_FIELD),
      gum_script_invocation_context_on_get_system_error,
      gum_script_invocation_context_on_set_system_error);
  context->SetAccessor (String::NewFromUtf8 (isolate, "threadId"),
      gum_script_invocation_context_on_get_thread_id);
  context->SetAccessor (String::NewFromUtf8 (isolate, "depth"),
      gum_script_invocation_context_on_get_depth);
  context->SetAccessor(String::NewFromUtf8(isolate, "context"),
	  gum_script_invocation_context_on_get_context, nullptr, data);
  self->invocation_context_value =
      new GumPersistent<Object>::type (isolate, context->NewInstance ());

  Handle<ObjectTemplate> args = ObjectTemplate::New (isolate);
  args->SetInternalFieldCount (1);
  args->SetIndexedPropertyHandler (
      gum_script_invocation_args_on_get_nth,
      gum_script_invocation_args_on_set_nth,
      0, 0, 0,
      data);
  self->invocation_args_value =
      new GumPersistent<Object>::type (isolate, args->NewInstance ());

  Local<FunctionTemplate> return_value = FunctionTemplate::New (isolate);
  return_value->SetClassName (String::NewFromUtf8 (isolate, "ReturnValue"));
  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (isolate,
      *self->core->native_pointer));
  return_value->Inherit (native_pointer);
  return_value->PrototypeTemplate ()->Set (
      String::NewFromUtf8 (isolate, "replace"), FunctionTemplate::New (isolate,
      gum_script_invocation_return_value_on_replace, data));
  return_value->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return_value = new GumPersistent<Object>::type (isolate, 
      return_value->GetFunction ()->NewInstance ());
}

void
_gum_script_interceptor_dispose (GumScriptInterceptor * self)
{
  gum_script_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);

  delete self->invocation_return_value;
  self->invocation_return_value = NULL;

  delete self->invocation_args_value;
  self->invocation_args_value = NULL;

  delete self->invocation_context_value;
  self->invocation_context_value = NULL;
}

void
_gum_script_interceptor_finalize (GumScriptInterceptor * self)
{
  g_queue_free (self->attach_entries);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

void
_gum_script_interceptor_on_enter (GumScriptInterceptor * self,
                                  GumInvocationContext * context)
{
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  ScriptScope scope (self->core->script);
  Isolate * isolate = self->core->isolate;

  Local<Object> invocation_context_value (Local<Object>::New (isolate,
      *self->invocation_context_value));
  Local<Object> receiver (invocation_context_value->Clone ());
  receiver->SetAlignedPointerInInternalField (0, context);
  receiver->SetInternalField (1, Integer::New (isolate, *depth));
  GumPersistent<Value>::type * persistent_receiver =
      new GumPersistent<Value>::type (isolate, receiver);
  *GUM_LINCTX_GET_FUNC_INVDATA (context,
      GumPersistent<Value>::type *) = persistent_receiver;

  if (entry->on_enter != NULL)
  {
    Local<Object> invocation_args_value (Local<Object>::New (isolate,
        *self->invocation_args_value));
    Local<Object> args (invocation_args_value->Clone ());
    args->SetAlignedPointerInInternalField (0, context);

    Local<Function> on_enter (Local<Function>::New (isolate, *entry->on_enter));
    Handle<Value> argv[] = { args };
    on_enter->Call (receiver, 1, argv);
  }

  (*depth)++;
}

void
_gum_script_interceptor_on_leave (GumScriptInterceptor * self,
                                  GumInvocationContext * context)
{
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  (*depth)--;

  ScriptScope scope (self->core->script);
  Isolate * isolate = self->core->isolate;

  GumPersistent<Value>::type * persistent_receiver =
    *GUM_LINCTX_GET_FUNC_INVDATA (context, GumPersistent<Value>::type *);
  Local<Value> receiver (Local<Value>::New (isolate, *persistent_receiver));

  if (entry->on_leave != NULL)
  {
    Local<Object> invocation_return_value (Local<Object>::New (isolate,
        *self->invocation_return_value));
    Local<Object> return_value (invocation_return_value->Clone ());
    return_value->SetInternalField (0, External::New (isolate,
        gum_invocation_context_get_return_value (context)));
    return_value->SetAlignedPointerInInternalField (1, context);

    Local<Function> on_leave (Local<Function>::New (isolate, *entry->on_leave));
    Handle<Value> argv[] = { return_value };
    on_leave->Call (receiver, 1, argv);
  }

  delete persistent_receiver;
}

static void
gum_script_interceptor_on_attach (const FunctionCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());
  GumScriptCore * core = self->core;
  Isolate * isolate = core->isolate;

  gpointer target;
  if (!_gum_script_pointer_get (info[0], &target, self->core))
    return;

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Interceptor.attach: second argument must be a callback object")));
    return;
  }

  Local<Function> on_enter, on_leave;

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get_opt (callbacks, "onEnter", &on_enter, core))
    return;
  if (!_gum_script_callbacks_get_opt (callbacks, "onLeave", &on_leave, core))
    return;

  GumScriptAttachEntry * entry = g_slice_new0 (GumScriptAttachEntry);
  if (!on_enter.IsEmpty ())
    entry->on_enter = new GumPersistent<Function>::type (isolate, on_enter);
  if (!on_leave.IsEmpty ())
    entry->on_leave = new GumPersistent<Function>::type (isolate, on_leave);

  /*
   * TODO: Create a helper object implementing the listener interface,
   *       and allow each to be detached invididually.
   */
  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      self->interceptor, target, GUM_INVOCATION_LISTENER (self->core->script),
      entry);

  g_queue_push_tail (self->attach_entries, entry);

  info.GetReturnValue ().Set (attach_ret == GUM_ATTACH_OK);
}

static void
gum_script_interceptor_on_detach_all (const FunctionCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());

  gum_script_interceptor_detach_all (self);
}

static void
gum_script_interceptor_detach_all (GumScriptInterceptor * self)
{
  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  while (!g_queue_is_empty (self->attach_entries))
  {
    GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
        g_queue_pop_tail (self->attach_entries));
    delete entry->on_enter;
    delete entry->on_leave;
    g_slice_free (GumScriptAttachEntry, entry);
  }
}

static void
gum_script_interceptor_on_replace (const FunctionCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gpointer target;
  if (!_gum_script_pointer_get (info[0], &target, self->core))
    return;

  gpointer replacement;
  if (!_gum_script_pointer_get (info[1], &replacement, self->core))
    return;

  GumScriptReplaceEntry * entry = g_slice_new (GumScriptReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = new GumPersistent<Value>::type (isolate, info[1]);

  gum_interceptor_replace_function (self->interceptor, target, replacement,
      NULL);

  g_hash_table_insert (self->replacement_by_address, target, entry);
}

static void
gum_script_interceptor_on_revert (const FunctionCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());

  gpointer target;
  if (!_gum_script_pointer_get (info[0], &target, self->core))
    return;

  g_hash_table_remove (self->replacement_by_address, target);
}

static void
gum_script_replace_entry_free (GumScriptReplaceEntry * entry)
{
  gum_interceptor_revert_function (entry->interceptor, entry->target);
  delete entry->replacement;
  g_slice_free (GumScriptReplaceEntry, entry);
}

static void
gum_script_invocation_context_on_get_system_error (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  (void) property;
  info.GetReturnValue ().Set (context->system_error);
}

static void
gum_script_invocation_context_on_set_system_error (Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  (void) property;
  context->system_error = value->Int32Value ();
}

static void
gum_script_invocation_context_on_get_thread_id (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  (void) property;
  info.GetReturnValue ().Set (gum_invocation_context_get_thread_id (context));
}

static void
gum_script_invocation_context_on_get_depth (Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  int32_t depth =
      info.Holder ()->GetInternalField (1).As <Integer> ()->Int32Value ();
  (void) property;
  info.GetReturnValue ().Set (depth);
}

static void
gum_script_invocation_context_on_get_context(Local<String> property,const PropertyCallbackInfo<Value> & info) {

	Isolate * isolate = info.GetIsolate();

	GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (info.Data().As<External>()->Value());
	GumInvocationContext * ctx = static_cast<GumInvocationContext *> (info.Holder()->GetAlignedPointerFromInternalField(0));

	(void)property;
	info.GetReturnValue().Set(Local<Value>::New(isolate, _gum_script_pointer_new(ctx->cpu_context, self->core)));
}

static void
gum_script_invocation_args_on_get_nth (uint32_t index,
                                       const PropertyCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  info.GetReturnValue ().Set (_gum_script_pointer_new (
      gum_invocation_context_get_nth_argument (ctx, index), self->core));
}

static void
gum_script_invocation_args_on_set_nth (uint32_t index,
                                       Local<Value> value,
                                       const PropertyCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));

  gpointer raw_value;
  if (!_gum_script_pointer_get (value, &raw_value, self->core))
    return;

  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);
}

static void
gum_script_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptInterceptor * self = static_cast<GumScriptInterceptor *> (
      info.Data ().As<External> ()->Value ());
  Local<Object> holder (info.Holder ());
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      holder->GetAlignedPointerFromInternalField (1));

  gpointer value;
  Local<FunctionTemplate> native_pointer (
      Local<FunctionTemplate>::New (info.GetIsolate (),
      *self->core->native_pointer));
  if (native_pointer->HasInstance (info[0]))
    value = GUM_NATIVE_POINTER_VALUE (info[0].As<Object> ());
  else
    value = GSIZE_TO_POINTER (info[0].As<Integer> ()->Value ());
  gum_invocation_context_replace_return_value (context, value);
  holder->SetInternalField (0, External::New (info.GetIsolate (), value));
}
