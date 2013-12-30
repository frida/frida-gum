/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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
  Persistent<Function> callback;
  Persistent<Object> receiver;
};

static Handle<Value> gum_script_stalker_on_get_trust_threshold (
    Local<String> property, const AccessorInfo & info);
static void gum_script_stalker_on_set_trust_threshold (Local<String> property,
    Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_stalker_on_get_queue_capacity (
    Local<String> property, const AccessorInfo & info);
static void gum_script_stalker_on_set_queue_capacity (Local<String> property,
    Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_stalker_on_get_queue_drain_interval (
    Local<String> property, const AccessorInfo & info);
static void gum_script_stalker_on_set_queue_drain_interval (
    Local<String> property, Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_stalker_on_garbage_collect (
    const Arguments & args);
static Handle<Value> gum_script_stalker_on_follow (const Arguments & args);
static Handle<Value> gum_script_stalker_on_unfollow (const Arguments & args);
static Handle<Value> gum_script_stalker_on_add_call_probe (
    const Arguments & args);
static Handle<Value> gum_script_stalker_on_remove_call_probe (
    const Arguments & args);
static void gum_script_call_probe_free (GumScriptCallProbe * probe);
static void gum_script_call_probe_fire (GumCallSite * site,
    gpointer user_data);
static Handle<Value> gum_script_probe_args_on_get_nth (uint32_t index,
    const AccessorInfo & info);

static gboolean gum_script_flags_get (Handle<Object> flags,
    const gchar * name);

void
_gum_script_stalker_init (GumScriptStalker * self,
                          GumScriptCore * core,
                          Handle<ObjectTemplate> scope)
{
  self->core = core;
  self->stalker = NULL;
  self->sink = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;
  self->pending_follow_level = 0;

  Handle<ObjectTemplate> stalker = ObjectTemplate::New ();
  stalker->SetAccessor (String::New ("trustThreshold"),
      gum_script_stalker_on_get_trust_threshold,
      gum_script_stalker_on_set_trust_threshold,
      External::Wrap (self));
  stalker->SetAccessor (String::New ("queueCapacity"),
      gum_script_stalker_on_get_queue_capacity,
      gum_script_stalker_on_set_queue_capacity,
      External::Wrap (self));
  stalker->SetAccessor (String::New ("queueDrainInterval"),
      gum_script_stalker_on_get_queue_drain_interval,
      gum_script_stalker_on_set_queue_drain_interval,
      External::Wrap (self));
  stalker->Set (String::New ("garbageCollect"),
      FunctionTemplate::New (gum_script_stalker_on_garbage_collect,
          External::Wrap (self)));
  stalker->Set (String::New ("follow"),
      FunctionTemplate::New (gum_script_stalker_on_follow,
          External::Wrap (self)));
  stalker->Set (String::New ("unfollow"),
      FunctionTemplate::New (gum_script_stalker_on_unfollow,
          External::Wrap (self)));
  stalker->Set (String::New ("addCallProbe"),
      FunctionTemplate::New (gum_script_stalker_on_add_call_probe,
          External::Wrap (self)));
  stalker->Set (String::New ("removeCallProbe"),
      FunctionTemplate::New (gum_script_stalker_on_remove_call_probe,
          External::Wrap (self)));
  scope->Set (String::New ("Stalker"), stalker);
}

void
_gum_script_stalker_realize (GumScriptStalker * self)
{
  Handle<ObjectTemplate> args_templ = ObjectTemplate::New ();
  args_templ->SetInternalFieldCount (2);
  args_templ->SetIndexedPropertyHandler (gum_script_probe_args_on_get_nth);
  self->probe_args = Persistent<ObjectTemplate>::New (args_templ);
}

void
_gum_script_stalker_dispose (GumScriptStalker * self)
{
  self->sink = NULL;

  if (self->stalker != NULL)
  {
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }

  self->probe_args.Dispose ();
  self->probe_args.Clear ();
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
    g_object_unref (self->sink);
    self->sink = NULL;
  }
}

static Handle<Value>
gum_script_stalker_on_get_trust_threshold (Local<String> property,
                                           const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  GumStalker * stalker = _gum_script_stalker_get (self);
  (void) property;
  return Number::New (gum_stalker_get_trust_threshold (stalker));
}

static void
gum_script_stalker_on_set_trust_threshold (Local<String> property,
                                           Local<Value> value,
                                           const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  GumStalker * stalker = _gum_script_stalker_get (self);
  (void) property;
  gum_stalker_set_trust_threshold (stalker, value->IntegerValue ());
}

static Handle<Value>
gum_script_stalker_on_get_queue_capacity (Local<String> property,
                                          const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  (void) property;
  return Number::New (self->queue_capacity);
}

static void
gum_script_stalker_on_set_queue_capacity (Local<String> property,
                                          Local<Value> value,
                                          const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  (void) property;
  self->queue_capacity = value->IntegerValue ();
}

static Handle<Value>
gum_script_stalker_on_get_queue_drain_interval (Local<String> property,
                                                const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  (void) property;
  return Number::New (self->queue_drain_interval);
}

static void
gum_script_stalker_on_set_queue_drain_interval (Local<String> property,
                                                Local<Value> value,
                                                const AccessorInfo & info)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (info.Data ()));
  (void) property;
  self->queue_drain_interval = value->IntegerValue ();
}

static Handle<Value>
gum_script_stalker_on_garbage_collect (const Arguments & args)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (args.Data ()));

  gum_stalker_garbage_collect (_gum_script_stalker_get (self));

  return Undefined ();
}

static Handle<Value>
gum_script_stalker_on_follow (const Arguments & args)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (args.Data ()));

  GumThreadId thread_id;
  Local<Value> options_value;
  switch (args.Length ())
  {
    case 0:
      thread_id = gum_process_get_current_thread_id ();
      break;
    case 1:
      if (args[0]->IsNumber ())
      {
        thread_id = args[0]->IntegerValue ();
      }
      else
      {
        thread_id = gum_process_get_current_thread_id ();
        options_value = args[0];
      }
      break;
    default:
      thread_id = args[0]->IntegerValue ();
      options_value = args[1];
      break;
  }

  GumScriptEventSinkOptions so;
  so.core = self->core;
  so.main_context = self->core->main_context;
  so.event_mask = GUM_NOTHING;
  so.queue_capacity = self->queue_capacity;
  so.queue_drain_interval = self->queue_drain_interval;

  if (!options_value.IsEmpty ())
  {
    if (!options_value->IsObject ())
    {
      ThrowException (Exception::TypeError (String::New ("Stalker.follow: "
          "options argument must be an object")));
      return Undefined ();
    }

    Local<Object> options = Local<Object>::Cast (options_value);

    Local<String> events_key (String::New ("events"));
    if (options->Has (events_key))
    {
      Local<Value> events_value (options->Get (events_key));
      if (!events_value->IsObject ())
      {
        ThrowException (Exception::TypeError (String::New ("Stalker.follow: "
            "events key must be an object")));
        return Undefined ();
      }

      Local<Object> events (Local<Object>::Cast (events_value));

      if (gum_script_flags_get (events, "call"))
        so.event_mask |= GUM_CALL;

      if (gum_script_flags_get (events, "ret"))
        so.event_mask |= GUM_RET;

      if (gum_script_flags_get (events, "exec"))
        so.event_mask |= GUM_EXEC;
    }

    if (so.event_mask != GUM_NOTHING &&
        !_gum_script_callbacks_get_opt (options, "onReceive", &so.on_receive))
    {
      return Undefined ();
    }

    if ((so.event_mask & GUM_CALL) != 0)
    {
      _gum_script_callbacks_get_opt (options, "onCallSummary",
          &so.on_call_summary);
    }
  }

  if (self->sink != NULL)
  {
    g_object_unref (self->sink);
    self->sink = NULL;
  }

  self->sink = gum_script_event_sink_new (&so);
  if (thread_id == gum_process_get_current_thread_id ())
  {
    self->pending_follow_level = 1;
  }
  else
  {
    gum_stalker_follow (_gum_script_stalker_get (self), thread_id,
        self->sink);
    g_object_unref (self->sink);
    self->sink = NULL;
  }

  return Undefined ();
}

static Handle<Value>
gum_script_stalker_on_unfollow (const Arguments & args)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (args.Data ()));
  GumStalker * stalker;
  GumThreadId thread_id;

  stalker = _gum_script_stalker_get (self);

  if (args.Length () > 0)
    thread_id = args[0]->IntegerValue ();
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

  return Undefined ();
}

static Handle<Value>
gum_script_stalker_on_add_call_probe (const Arguments & args)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (args.Data ()));
  GumScriptCallProbe * probe;
  GumProbeId id;

  gpointer target_address;
  if (!_gum_script_pointer_get (self->core, args[0], &target_address))
    return Undefined ();

  Local<Value> callback_value = args[1];
  if (!callback_value->IsFunction ())
  {
    ThrowException (Exception::TypeError (String::New ("Stalker.addCallProbe: "
        "second argument must be a function")));
    return Undefined ();
  }
  Local<Function> callback = Local<Function>::Cast (callback_value);

  probe = g_slice_new (GumScriptCallProbe);
  probe->parent = self;
  probe->callback = Persistent<Function>::New (callback);
  probe->receiver = Persistent<Object>::New (args.This ());
  id = gum_stalker_add_call_probe (_gum_script_stalker_get (self),
      target_address, gum_script_call_probe_fire,
      probe, reinterpret_cast<GDestroyNotify> (gum_script_call_probe_free));

  return Uint32::New (id);
}

static Handle<Value>
gum_script_stalker_on_remove_call_probe (const Arguments & args)
{
  GumScriptStalker * self = static_cast<GumScriptStalker *> (
      External::Unwrap (args.Data ()));

  Local<Value> id = args[0];
  if (!id->IsUint32 ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Stalker.removeCallProbe: argument must be a probe id")));
    return Undefined ();
  }

  gum_stalker_remove_call_probe (_gum_script_stalker_get (self),
      id->ToUint32 ()->Value ());

  return Undefined ();
}

static void
gum_script_call_probe_free (GumScriptCallProbe * probe)
{
  ScriptScope scope (probe->parent->core->script);
  probe->callback.Dispose ();
  probe->receiver.Dispose ();
  g_slice_free (GumScriptCallProbe, probe);
}

static void
gum_script_call_probe_fire (GumCallSite * site,
                            gpointer user_data)
{
  GumScriptCallProbe * self = static_cast<GumScriptCallProbe *> (user_data);

  ScriptScope scope (self->parent->core->script);
  Local<Object> args = self->parent->probe_args->NewInstance ();
  args->SetPointerInInternalField (0, self);
  args->SetPointerInInternalField (1, site);
  Handle<Value> argv[] = { args };
  self->callback->Call (self->receiver, 1, argv);
}

static Handle<Value>
gum_script_probe_args_on_get_nth (uint32_t index,
                                  const AccessorInfo & info)
{
  Handle<Object> instance = info.This ();
  GumScriptCallProbe * self = static_cast<GumScriptCallProbe *> (
      instance->GetPointerFromInternalField (0));
  GumCallSite * site = static_cast<GumCallSite *> (
      instance->GetPointerFromInternalField (1));
  gsize value;
  gsize * stack_argument = static_cast<gsize *> (site->stack_data);

#if GLIB_SIZEOF_VOID_P == 8
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

  return _gum_script_pointer_new (self->parent->core,
      GSIZE_TO_POINTER (value));
}

static gboolean
gum_script_flags_get (Handle<Object> flags,
                      const gchar * name)
{
  Local<String> key (String::New (name));
  return flags->Has (key) && flags->Get (key)->ToBoolean ()->BooleanValue ();
}

