/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptthread.h"

using namespace v8;

static void gum_script_thread_on_backtrace (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_thread_on_sleep (
    const FunctionCallbackInfo<Value> & info);

void
_gum_script_thread_init (GumScriptThread * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Handle<ObjectTemplate> thread = ObjectTemplate::New (isolate);
  thread->Set (String::NewFromUtf8 (isolate, "backtrace"),
      FunctionTemplate::New (isolate, gum_script_thread_on_backtrace,
      External::New (isolate, self)));
  thread->Set (String::NewFromUtf8 (isolate, "sleep"),
      FunctionTemplate::New (isolate, gum_script_thread_on_sleep,
      External::New (isolate, self)));
  scope->Set (String::NewFromUtf8 (isolate, "Thread"), thread);

  Handle<ObjectTemplate> backtracer = ObjectTemplate::New (isolate);
  Local<Symbol> accurate = Symbol::ForApi (isolate,
      String::NewFromUtf8 (isolate, "Backtracer.ACCURATE"));
  backtracer->Set (String::NewFromUtf8 (isolate, "ACCURATE"), accurate,
      static_cast<PropertyAttribute> (ReadOnly | DontDelete));
  Local<Symbol> fuzzy = Symbol::ForApi (isolate,
      String::NewFromUtf8 (isolate, "Backtracer.FUZZY"));
  backtracer->Set (String::NewFromUtf8 (isolate, "FUZZY"), fuzzy,
      static_cast<PropertyAttribute> (ReadOnly | DontDelete));
  scope->Set (String::NewFromUtf8 (isolate, "Backtracer"), backtracer);

  self->accurate_enum_value =
      new GumPersistent<Symbol>::type (isolate, accurate);
  self->fuzzy_enum_value =
      new GumPersistent<Symbol>::type (isolate, fuzzy);
}

void
_gum_script_thread_realize (GumScriptThread * self)
{
  (void) self;
}

void
_gum_script_thread_dispose (GumScriptThread * self)
{
  (void) self;
}

void
_gum_script_thread_finalize (GumScriptThread * self)
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

  delete self->fuzzy_enum_value;
  self->fuzzy_enum_value = NULL;

  delete self->accurate_enum_value;
  self->accurate_enum_value = NULL;
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
gum_script_thread_on_backtrace (const FunctionCallbackInfo<Value> & info)
{
  GumScriptThread * self = static_cast<GumScriptThread *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  int num_args = info.Length ();

  GumCpuContext * cpu_context = NULL;
  if (num_args >= 1)
  {
    Local<Value> value = info[0];
    if (!value->IsNull ())
    {
      if (!_gum_script_cpu_context_get (value, &cpu_context, self->core))
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
    result->Set (i, _gum_script_pointer_new (ret_addrs.items[i], self->core));
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
gum_script_thread_on_sleep (const FunctionCallbackInfo<Value> & info)
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

  isolate->Exit ();
  {
    Unlocker ul (isolate);
    g_usleep (delay * G_USEC_PER_SEC);
  }
  isolate->Enter ();
}
