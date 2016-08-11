/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8thread.h"

using namespace v8;

static void gum_v8_thread_on_backtrace (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_thread_on_sleep (
    const FunctionCallbackInfo<Value> & info);

void
_gum_v8_thread_init (GumV8Thread * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Handle<ObjectTemplate> thread = ObjectTemplate::New (isolate);
  thread->Set (String::NewFromUtf8 (isolate, "backtrace"),
      FunctionTemplate::New (isolate, gum_v8_thread_on_backtrace,
      External::New (isolate, self)));
  thread->Set (String::NewFromUtf8 (isolate, "sleep"),
      FunctionTemplate::New (isolate, gum_v8_thread_on_sleep,
      External::New (isolate, self)));
  scope->Set (String::NewFromUtf8 (isolate, "Thread"), thread);

  Handle<ObjectTemplate> backtracer = ObjectTemplate::New (isolate);
  scope->Set (String::NewFromUtf8 (isolate, "Backtracer"), backtracer);
}

void
_gum_v8_thread_realize (GumV8Thread * self)
{
  Isolate * isolate = self->core->isolate;
  Local<Context> context (isolate->GetCurrentContext ());
  Local<Object> global (context->Global ());

  Local<Object> backtracer = global->Get (context,
      String::NewFromUtf8 (isolate, "Backtracer")).ToLocalChecked ()
      .As<Object> ();
  Local<Symbol> accurate = Symbol::ForApi (isolate,
      String::NewFromUtf8 (isolate, "Backtracer.ACCURATE"));
  backtracer->DefineOwnProperty (context,
      String::NewFromUtf8 (isolate, "ACCURATE"), accurate,
      static_cast<PropertyAttribute> (ReadOnly | DontDelete)).ToChecked ();
  Local<Symbol> fuzzy = Symbol::ForApi (isolate,
      String::NewFromUtf8 (isolate, "Backtracer.FUZZY"));
  backtracer->DefineOwnProperty (context,
      String::NewFromUtf8 (isolate, "FUZZY"), fuzzy,
      static_cast<PropertyAttribute> (ReadOnly | DontDelete)).ToChecked ();

  self->accurate_enum_value =
      new GumPersistent<Symbol>::type (isolate, accurate);
  self->fuzzy_enum_value =
      new GumPersistent<Symbol>::type (isolate, fuzzy);
}

void
_gum_v8_thread_dispose (GumV8Thread * self)
{
  delete self->fuzzy_enum_value;
  self->fuzzy_enum_value = NULL;

  delete self->accurate_enum_value;
  self->accurate_enum_value = NULL;
}

void
_gum_v8_thread_finalize (GumV8Thread * self)
{
  if (self->accurate_backtracer != NULL)
  {
    g_object_unref (self->accurate_backtracer);
    self->accurate_backtracer = NULL;
  }

  if (self->fuzzy_backtracer != NULL)
  {
    g_object_unref (self->fuzzy_backtracer);
    self->fuzzy_backtracer = NULL;
  }
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
gum_v8_thread_on_backtrace (const FunctionCallbackInfo<Value> & info)
{
  GumV8Thread * self = static_cast<GumV8Thread *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  int num_args = info.Length ();

  GumCpuContext * cpu_context = NULL;
  if (num_args >= 1)
  {
    Local<Value> value = info[0];
    if (!value->IsNull ())
    {
      if (!_gum_v8_cpu_context_get (value, &cpu_context, self->core))
        return;
    }
  }

  bool accurate = true;
  if (num_args >= 2)
  {
    Local<Value> selector = info[1];
    if (!selector->IsNull ())
    {
      if ((*self->fuzzy_enum_value) == selector)
      {
        accurate = false;
      }
      else if ((*self->accurate_enum_value) != selector)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "Thread.backtrace: invalid backtracer enum value")));
        return;
      }
    }
  }

  GumBacktracer * backtracer;
  if (accurate)
  {
    if (self->accurate_backtracer == NULL)
      self->accurate_backtracer = gum_backtracer_make_accurate ();
    backtracer = self->accurate_backtracer;
  }
  else
  {
    if (self->fuzzy_backtracer == NULL)
      self->fuzzy_backtracer = gum_backtracer_make_fuzzy ();
    backtracer = self->fuzzy_backtracer;
  }
  if (backtracer == NULL)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, accurate
        ? "Thread.backtrace: backtracer not yet available for this "
        "platform; please try Thread.backtrace(context, Backtracer.FUZZY)"
        : "Thread.backtrace: backtracer not yet available for this "
        "platform; please try Thread.backtrace(context, Backtracer.ACCURATE)"
        )));
    return;
  }

  GumReturnAddressArray ret_addrs;
  gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);

  Local<Array> result = Array::New (isolate, ret_addrs.len);
  for (guint i = 0; i != ret_addrs.len; i++)
    result->Set (i, _gum_v8_native_pointer_new (ret_addrs.items[i], self->core));
  info.GetReturnValue ().Set (result);
}

/*
 * Prototype:
 * Thread.sleep(delay)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_thread_on_sleep (const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();

  Local<Value> delay_val = info[0];
  if (!delay_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Thread.sleep: argument must be a number specifying delay")));
    return;
  }
  double delay = delay_val->ToNumber ()->Value ();
  if (delay < 0)
    return;

  isolate->Exit ();
  {
    Unlocker ul (isolate);
    g_usleep (delay * G_USEC_PER_SEC);
  }
  isolate->Enter ();
}
