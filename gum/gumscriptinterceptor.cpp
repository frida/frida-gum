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

#include "gumscriptinterceptor.h"

#include "gumscriptscope.h"

using namespace v8;

typedef struct _GumScriptAttachEntry GumScriptAttachEntry;
typedef struct _GumScriptReplaceEntry GumScriptReplaceEntry;

struct _GumScriptAttachEntry
{
  Persistent<Function> on_enter;
  Persistent<Function> on_leave;
};

struct _GumScriptReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  Persistent<Value> replacement;
};

static Handle<Value> gum_script_interceptor_on_attach (const Arguments & args);
static Handle<Value> gum_script_interceptor_on_detach_all (
    const Arguments & args);
static void gum_script_interceptor_detach_all (GumScriptInterceptor * self);
static Handle<Value> gum_script_interceptor_on_replace (const Arguments & args);
static Handle<Value> gum_script_interceptor_on_revert (const Arguments & args);
static void gum_script_replace_entry_free (GumScriptReplaceEntry * entry);

static Handle<Value> gum_script_invocation_args_on_get_nth (uint32_t index,
    const AccessorInfo & info);
static Handle<Value> gum_script_invocation_args_on_set_nth (uint32_t index,
    Local<Value> value, const AccessorInfo & info);

void
_gum_script_interceptor_init (GumScriptInterceptor * self,
                              GumScriptCore * core,
                              Handle<ObjectTemplate> scope)
{
  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->attach_entries = g_queue_new ();
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_script_replace_entry_free));

  Handle<ObjectTemplate> interceptor = ObjectTemplate::New ();
  interceptor->Set (String::New ("attach"), FunctionTemplate::New (
      gum_script_interceptor_on_attach, External::Wrap (self)));
  interceptor->Set (String::New ("detachAll"), FunctionTemplate::New (
      gum_script_interceptor_on_detach_all, External::Wrap (self)));
  interceptor->Set (String::New ("replace"), FunctionTemplate::New (
      gum_script_interceptor_on_replace, External::Wrap (self)));
  interceptor->Set (String::New ("revert"), FunctionTemplate::New (
      gum_script_interceptor_on_revert, External::Wrap (self)));
  scope->Set (String::New ("Interceptor"), interceptor);
}

void
_gum_script_interceptor_realize (GumScriptInterceptor * self)
{
  Handle<ObjectTemplate> args = ObjectTemplate::New ();
  args->SetInternalFieldCount (1);
  args->SetIndexedPropertyHandler (
      gum_script_invocation_args_on_get_nth,
      gum_script_invocation_args_on_set_nth,
      0, 0, 0,
      External::Wrap (self));
  self->invocation_args = Persistent<ObjectTemplate>::New (args);
}

void
_gum_script_interceptor_dispose (GumScriptInterceptor * self)
{
  gum_script_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);
}

void
_gum_script_interceptor_finalize (GumScriptInterceptor * self)
{
  self->invocation_args.Dispose ();
  self->invocation_args.Clear ();

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

  Persistent<Object> receiver = Persistent<Object>::New (Object::New ());
  receiver->Set (String::New ("threadId"),
      Int32::New (gum_invocation_context_get_thread_id (context)),
      ReadOnly);
  receiver->Set (String::New ("depth"), Int32::New (*depth), ReadOnly);
  *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *) = *receiver;

  if (!entry->on_enter.IsEmpty ())
  {
    Local<Object> args = self->invocation_args->NewInstance ();
    args->SetPointerInInternalField (0, context);

    Handle<Value> argv[] = { args };
    entry->on_enter->Call (receiver, 1, argv);
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

  Persistent<Object> receiver (
      *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *));

  if (!entry->on_leave.IsEmpty ())
  {
    gpointer raw_value = gum_invocation_context_get_return_value (context);
    Handle<Object> return_value (_gum_script_pointer_new (self->core,
        raw_value));

    Handle<Value> argv[] = { return_value };
    entry->on_leave->Call (receiver, 1, argv);
  }

  receiver.Dispose ();
}

static Handle<Value>
gum_script_interceptor_on_attach (const Arguments & args)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (args.Data ()));

  gpointer target;
  if (!_gum_script_pointer_get (self->core, args[0], &target))
    return Undefined ();

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New ("Interceptor.attach: "
        "second argument must be a callback object")));
    return Undefined ();
  }

  Local<Function> on_enter, on_leave;

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get_opt (callbacks, "onEnter", &on_enter))
    return Undefined ();
  if (!_gum_script_callbacks_get_opt (callbacks, "onLeave", &on_leave))
    return Undefined ();

  GumScriptAttachEntry * entry = g_slice_new (GumScriptAttachEntry);
  entry->on_enter = Persistent<Function>::New (on_enter);
  entry->on_leave = Persistent<Function>::New (on_leave);

  /*
   * FIXME: Create a helper object implementing the listener interface,
   *        and allow each to be detached invididually.
   */
  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      self->interceptor, target, GUM_INVOCATION_LISTENER (self->core->script),
      entry);

  g_queue_push_tail (self->attach_entries, entry);

  return (attach_ret == GUM_ATTACH_OK) ? True () : False ();
}

static Handle<Value>
gum_script_interceptor_on_detach_all (const Arguments & args)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (args.Data ()));

  gum_script_interceptor_detach_all (self);

  return Undefined ();
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
    entry->on_enter.Dispose ();
    entry->on_leave.Dispose ();
    g_slice_free (GumScriptAttachEntry, entry);
  }
}

static Handle<Value>
gum_script_interceptor_on_replace (const Arguments & args)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (args.Data ()));

  gpointer target;
  if (!_gum_script_pointer_get (self->core, args[0], &target))
    return Undefined ();

  gpointer replacement;
  if (!_gum_script_pointer_get (self->core, args[1], &replacement))
    return Undefined ();

  GumScriptReplaceEntry * entry = g_slice_new (GumScriptReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = Persistent<Value>::New (args[1]);

  gum_interceptor_replace_function (self->interceptor, target, replacement,
      NULL);

  g_hash_table_insert (self->replacement_by_address, target, entry);

  return Undefined ();
}

static Handle<Value>
gum_script_interceptor_on_revert (const Arguments & args)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (args.Data ()));

  gpointer target;
  if (!_gum_script_pointer_get (self->core, args[0], &target))
    return Undefined ();

  g_hash_table_remove (self->replacement_by_address, target);

  return Undefined ();
}

static void
gum_script_replace_entry_free (GumScriptReplaceEntry * entry)
{
  gum_interceptor_revert_function (entry->interceptor, entry->target);
  entry->replacement.Dispose ();
  g_slice_free (GumScriptReplaceEntry, entry);
}

static Handle<Value>
gum_script_invocation_args_on_get_nth (uint32_t index,
                                       const AccessorInfo & info)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (info.Data ()));
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));
  return _gum_script_pointer_new (self->core,
      gum_invocation_context_get_nth_argument (ctx, index));
}

static Handle<Value>
gum_script_invocation_args_on_set_nth (uint32_t index,
                                       Local<Value> value,
                                       const AccessorInfo & info)
{
  GumScriptInterceptor * self =
      static_cast<GumScriptInterceptor *> (External::Unwrap (info.Data ()));
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));

  gpointer raw_value;
  if (!_gum_script_pointer_get (self->core, value, &raw_value))
    return Undefined ();

  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);

  return value;
}

