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

#include "gumscriptthread.h"

using namespace v8;

static Handle<Value> gum_script_thread_on_sleep (const Arguments & args);

void
_gum_script_thread_init (GumScriptThread * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  self->core = core;

  Handle<ObjectTemplate> thread = ObjectTemplate::New ();
  thread->Set (String::New ("sleep"),
      FunctionTemplate::New (gum_script_thread_on_sleep,
          External::Wrap (self)));
  scope->Set (String::New ("Thread"), thread);
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
  (void) self;
}

static Handle<Value>
gum_script_thread_on_sleep (const Arguments & args)
{
  GumScriptThread * self = static_cast<GumScriptThread *> (
      External::Unwrap (args.Data ()));

  Local<Value> delay_val = args[0];
  if (!delay_val->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Thread.sleep: argument must be a number specifying delay")));
    return Undefined ();
  }
  double delay = delay_val->ToNumber ()->Value ();

  self->core->isolate->Exit ();
  {
    Unlocker ul (self->core->isolate);
    g_usleep (delay * G_USEC_PER_SEC);
  }
  self->core->isolate->Enter ();

  return Undefined ();
}

