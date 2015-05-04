/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptstalker.h"

#include "gumscriptcore.h"
#include "gumscripteventsink.h"
#include "gumscriptscope.h"

using namespace v8;

typedef struct _GumScriptCallProbe GumScriptCallProbe;

struct _GumScriptCallProbe
{
  GumScriptStalker * parent;
  GumPersistent<Function>::type * callback;
  GumPersistent<Value>::type * receiver;
};

static void gum_script_stalker_on_get_trust_threshold (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_stalker_on_set_trust_threshold (Local<String> property,
    Local<Value> value, const PropertyCallbackInfo<void> & info);
static void gum_script_stalker_on_get_queue_capacity (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_stalker_on_set_queue_capacity (Local<String> property,
    Local<Value> value, const PropertyCallbackInfo<void> & info);
static void gum_script_stalker_on_get_queue_drain_interval (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_script_stalker_on_set_queue_drain_interval (
    Local<String> property, Local<Value> value,
    const PropertyCallbackInfo<void> & info);
static void gum_script_stalker_on_garbage_collect (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_stalker_on_follow (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_stalker_on_unfollow (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_stalker_on_add_call_probe (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_stalker_on_remove_call_probe (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_call_probe_free (GumScriptCallProbe * probe);
static void gum_script_call_probe_fire (GumCallSite * site,
    gpointer user_data);
static void gum_script_probe_args_on_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);

static gboolean gum_script_flags_get (Handle<Object> flags,
    const gchar * name, GumScriptCore * core);

void
_gum_script_stalker_init (GumScriptStalker * self,
                          GumScriptCore * core,
                          Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;
  self->stalker = NULL;
  self->sink = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;
  self->pending_follow_level = 0;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> stalker = ObjectTemplate::New (isolate);
  stalker->SetAccessor (String::NewFromUtf8 (isolate, "trustThreshold"),
      gum_script_stalker_on_get_trust_threshold,
      gum_script_stalker_on_set_trust_threshold,
      data);
  stalker->SetAccessor (String::NewFromUtf8 (isolate, "queueCapacity"),
      gum_script_stalker_on_get_queue_capacity,
      gum_script_stalker_on_set_queue_capacity,
      data);
  stalker->SetAccessor (String::NewFromUtf8 (isolate, "queueDrainInterval"),
      gum_script_stalker_on_get_queue_drain_interval,
      gum_script_stalker_on_set_queue_drain_interval,
      data);
  stalker->Set (String::NewFromUtf8 (isolate, "garbageCollect"),
      FunctionTemplate::New (isolate, gum_script_stalker_on_garbage_collect,
      data));
  stalker->Set (String::NewFromUtf8 (isolate, "follow"),
      FunctionTemplate::New (isolate, gum_script_stalker_on_follow,
      data));
  stalker->Set (String::NewFromUtf8 (isolate, "unfollow"),
      FunctionTemplate::New (isolate, gum_script_stalker_on_unfollow,
      data));
  stalker->Set (String::NewFromUtf8 (isolate, "addCallProbe"),
      FunctionTemplate::New (isolate, gum_script_stalker_on_add_call_probe,
      data));
  stalker->Set (String::NewFromUtf8 (isolate, "removeCallProbe"),
      FunctionTemplate::New (isolate, gum_script_stalker_on_remove_call_probe,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Stalker"), stalker);
}

void
_gum_script_stalker_realize (GumScriptStalker * self)
{
  Isolate * isolate = self->core->isolate;

  Handle<ObjectTemplate> args_templ = ObjectTemplate::New (isolate);
  args_templ->SetInternalFieldCount (2);
  args_templ->SetIndexedPropertyHandler (gum_script_probe_args_on_get_nth);
  self->probe_args =
      new GumPersistent<ObjectTemplate>::type(isolate, args_templ);
}

void
_gum_script_stalker_flush (GumScriptStalker * self)
{
  if (self->sink != NULL)
  {
    GumEventSink * sink = self->sink;
    self->sink = NULL;
    g_object_unref (sink);
  }

  if (self->stalker != NULL)
  {
    gum_stalker_stop (self->stalker);
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

void
_gum_script_stalker_dispose (GumScriptStalker * self)
{
  delete self->probe_args;
  self->probe_args = NULL;
}

void
_gum_script_stalker_finalize (GumScriptStalker * self)
{
  (void) self;
}

GumStalker *
_gum_script_stalker_get (GumScriptStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_script_stalker_process_pending (GumScriptStalker * self)
{
  if (self->pending_follow_level > 0)
  {
    gum_stalker_follow_me (_gum_script_stalker_get (self), self->sink);
  }
  else if (self->pending_follow_level < 0)
  {
    gum_stalker_unfollow_me (_gum_script_stalker_get (self));
  }
  self->pending_follow_level = 0;

  if (self->sink != NULL)
  {
    GumEventSink * sink = self->sink;
    self->sink = NULL;
    g_object_unref (sink);
  }
}

static void
gum_script_stalker_on_get_trust_threshold (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  GumStalker * stalker = _gum_script_stalker_get (self);
  (void) property;
  info.GetReturnValue ().Set (gum_stalker_get_trust_threshold (stalker));
}

static void
gum_script_stalker_on_set_trust_threshold (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  GumStalker * stalker = _gum_script_stalker_get (self);
  (void) property;
  gum_stalker_set_trust_threshold (stalker, value->IntegerValue ());
}

static void
gum_script_stalker_on_get_queue_capacity (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  (void) property;
  info.GetReturnValue ().Set (self->queue_capacity);
}

static void
gum_script_stalker_on_set_queue_capacity (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  (void) property;
  self->queue_capacity = value->IntegerValue ();
}

static void
gum_script_stalker_on_get_queue_drain_interval (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  (void) property;
  info.GetReturnValue ().Set (self->queue_drain_interval);
}

static void
gum_script_stalker_on_set_queue_drain_interval (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  (void) property;
  self->queue_drain_interval = value->IntegerValue ();
}

/*
 * Prototype:
 * Stalker.garbageCollect()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_stalker_on_garbage_collect (const FunctionCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());

  gum_stalker_garbage_collect (_gum_script_stalker_get (self));
}

/*
 * Prototype:
 * TBW
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_stalker_on_follow (const FunctionCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  GumScriptCore * core = self->core;
  Isolate * isolate = info.GetIsolate ();

  GumThreadId thread_id;
  Local<Value> options_value;
  switch (info.Length ())
  {
    case 0:
      thread_id = gum_process_get_current_thread_id ();
      break;
    case 1:
      if (info[0]->IsNumber ())
      {
        thread_id = info[0]->IntegerValue ();
      }
      else
      {
        thread_id = gum_process_get_current_thread_id ();
        options_value = info[0];
      }
      break;
    default:
      thread_id = info[0]->IntegerValue ();
      options_value = info[1];
      break;
  }

  GumScriptEventSinkOptions so;
  so.core = self->core;
  so.main_context = gum_script_scheduler_get_v8_context (self->core->scheduler);
  so.event_mask = GUM_NOTHING;
  so.queue_capacity = self->queue_capacity;
  so.queue_drain_interval = self->queue_drain_interval;

  if (!options_value.IsEmpty ())
  {
    if (!options_value->IsObject ())
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "Stalker.follow: options argument must be an object")));
      return;
    }

    Local<Object> options = Local<Object>::Cast (options_value);

    Local<String> events_key (String::NewFromUtf8 (isolate, "events"));
    if (options->Has (events_key))
    {
      Local<Value> events_value (options->Get (events_key));
      if (!events_value->IsObject ())
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "Stalker.follow: events key must be an object")));
        return;
      }

      Local<Object> events (Local<Object>::Cast (events_value));

      if (gum_script_flags_get (events, "call", core))
        so.event_mask |= GUM_CALL;

      if (gum_script_flags_get (events, "ret", core))
        so.event_mask |= GUM_RET;

      if (gum_script_flags_get (events, "exec", core))
        so.event_mask |= GUM_EXEC;
    }

    if (so.event_mask != GUM_NOTHING &&
        !_gum_script_callbacks_get_opt (options, "onReceive", &so.on_receive,
        core))
    {
      return;
    }

    if ((so.event_mask & GUM_CALL) != 0)
    {
      _gum_script_callbacks_get_opt (options, "onCallSummary",
          &so.on_call_summary, core);
    }
  }

  if (self->sink != NULL)
  {
    GumEventSink * sink = self->sink;
    self->sink = NULL;
    g_object_unref (sink);
  }

  self->sink = gum_script_event_sink_new (&so);
  if (thread_id == gum_process_get_current_thread_id ())
  {
    self->pending_follow_level = 1;
  }
  else
  {
    GumEventSink * sink = self->sink;
    self->sink = NULL;
    gum_stalker_follow (_gum_script_stalker_get (self), thread_id, sink);
    g_object_unref (sink);
  }
}

/*
 * Prototype:
 * Stalker.unfollow(thread_id)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_stalker_on_unfollow (const FunctionCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  GumStalker * stalker;
  GumThreadId thread_id;

  stalker = _gum_script_stalker_get (self);

  if (info.Length () > 0)
    thread_id = info[0]->IntegerValue ();
  else
    thread_id = gum_process_get_current_thread_id ();

  if (thread_id == gum_process_get_current_thread_id ())
  {
    self->pending_follow_level--;
  }
  else
  {
    gum_stalker_unfollow (stalker, thread_id);
  }
}

/*
 * Prototype:
 * Stalker.addCallProbe(target_address, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_stalker_on_add_call_probe (const FunctionCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();
  GumScriptCallProbe * probe;
  GumProbeId id;

  gpointer target_address;
  if (!_gum_script_pointer_get (info[0], &target_address, self->core))
    return;

  Local<Value> callback_value = info[1];
  if (!callback_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Stalker.addCallProbe: second argument must be a function")));
    return;
  }
  Local<Function> callback = Local<Function>::Cast (callback_value);

  probe = g_slice_new (GumScriptCallProbe);
  probe->parent = self;
  probe->callback = new GumPersistent<Function>::type (isolate, callback);
  probe->receiver = new GumPersistent<Value>::type (isolate, info.This ());
  id = gum_stalker_add_call_probe (_gum_script_stalker_get (self),
      target_address, gum_script_call_probe_fire,
      probe, reinterpret_cast<GDestroyNotify> (gum_script_call_probe_free));

  info.GetReturnValue ().Set (id);
}

/*
 * Prototype:
 * Stalker.removeCallProbe(id)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_stalker_on_remove_call_probe (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> id = info[0];
  if (!id->IsUint32 ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Stalker.removeCallProbe: argument must be a probe id")));
    return;
  }

  gum_stalker_remove_call_probe (_gum_script_stalker_get (self),
      id->ToUint32 ()->Value ());

  return;
}

static void
gum_script_call_probe_free (GumScriptCallProbe * probe)
{
  ScriptScope scope (probe->parent->core->script);
  delete probe->callback;
  delete probe->receiver;
  g_slice_free (GumScriptCallProbe, probe);
}

static void
gum_script_call_probe_fire (GumCallSite * site,
                            gpointer user_data)
{
  GumScriptCallProbe * self = static_cast<GumScriptCallProbe *> (user_data);

  ScriptScope scope (self->parent->core->script);
  Isolate * isolate = self->parent->core->isolate;

  Local<ObjectTemplate> probe_args (
      Local<ObjectTemplate>::New (isolate, *self->parent->probe_args));
  Local<Object> args = probe_args->NewInstance ();
  args->SetAlignedPointerInInternalField (0, self);
  args->SetAlignedPointerInInternalField (1, site);

  Local<Function> callback (Local<Function>::New (isolate, *self->callback));
  Local<Value> receiver (Local<Value>::New (isolate, *self->receiver));
  Handle<Value> argv[] = { args };
  callback->Call (receiver, 1, argv);
}

static void
gum_script_probe_args_on_get_nth (uint32_t index,
                                  const PropertyCallbackInfo<Value> & info)
{
  Handle<Object> instance = info.This ();
  GumScriptCallProbe * self = static_cast<GumScriptCallProbe *> (
      instance->GetAlignedPointerFromInternalField (0));
  GumCallSite * site = static_cast<GumCallSite *> (
      instance->GetAlignedPointerFromInternalField (1));
  gsize value;
  gsize * stack_argument = static_cast<gsize *> (site->stack_data);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  switch (index)
  {
# if GUM_NATIVE_ABI_IS_UNIX
    case 0: value = site->cpu_context->rdi; break;
    case 1: value = site->cpu_context->rsi; break;
    case 2: value = site->cpu_context->rdx; break;
    case 3: value = site->cpu_context->rcx; break;
    case 4: value = site->cpu_context->r8;  break;
    case 5: value = site->cpu_context->r9;  break;
    default:
      value = stack_argument[index - 6];
      break;
# else
    case 0: value = site->cpu_context->rcx; break;
    case 1: value = site->cpu_context->rdx; break;
    case 2: value = site->cpu_context->r8;  break;
    case 3: value = site->cpu_context->r9;  break;
    default:
      value = stack_argument[index];
      break;
# endif
  }
#else
  value = stack_argument[index];
#endif

  info.GetReturnValue ().Set (
      _gum_script_pointer_new (GSIZE_TO_POINTER (value), self->parent->core));
}

static gboolean
gum_script_flags_get (Handle<Object> flags,
                      const gchar * name,
                      GumScriptCore * core)
{
  Local<String> key (String::NewFromUtf8 (core->isolate, name));
  return flags->Has (key) && flags->Get (key)->ToBoolean ()->BooleanValue ();
}
