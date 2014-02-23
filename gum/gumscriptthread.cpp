/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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
  thread->Set (String::NewFromUtf8 (isolate, "sleep"),
      FunctionTemplate::New (isolate, gum_script_thread_on_sleep,
      External::New (isolate, self)));
  scope->Set (String::NewFromUtf8 (isolate, "Thread"), thread);
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
