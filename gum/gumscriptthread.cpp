/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptthread.h"

using namespace v8;

static void gum_script_thread_on_sleep (
    const FunctionCallbackInfo<Value> & info);

static void gum_script_thread_on_backtrace(
	const FunctionCallbackInfo<Value> & info);

void
_gum_script_thread_init (GumScriptThread * self,
                         GumScriptCore * core,
                         Handle<ObjectTemplate> scope)
{
  
  self->core = core;
  Isolate * isolate = core->isolate;
  Local<External> data(External::New(isolate, self));
  Handle<ObjectTemplate> thread = ObjectTemplate::New (isolate);
  thread->Set (String::NewFromUtf8 (isolate, "sleep"),FunctionTemplate::New (isolate, gum_script_thread_on_sleep,data));
  thread->Set(String::NewFromUtf8(isolate, "backtrace"), FunctionTemplate::New(isolate, gum_script_thread_on_backtrace,data));

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

#define MAX_BACKTRACE_STR (10*1024)

static void generate_backtrace_string(GumReturnAddressArray * ret_addrs, char* trace) {

	char tmp[1024];

	for (guint i = 0; i != ret_addrs->len; i++) {
		GumReturnAddress * ra = (GumReturnAddress *)ret_addrs->items[i];
		GumReturnAddressDetails rad;

		if (gum_return_address_details_from_address(ra, &rad)) {
			sprintf_s(tmp, 1024, "%p %s!%s\n", rad.address, rad.module_name, rad.function_name);
			strcat_s(trace, MAX_BACKTRACE_STR, tmp);
		}
		else {
			sprintf_s(tmp, 1024,"%p <unknown>\n", ra);
			strcat_s(trace, MAX_BACKTRACE_STR, tmp);
		}
	}
}

static void gum_script_thread_on_backtrace(const FunctionCallbackInfo<Value> & info) {
	
	GumScriptThread* self = static_cast<GumScriptThread *> (info.Data().As<External>()->Value());	
	GumScriptCore * core = self->core;

	gpointer ptr_cpu_context;
	_gum_script_pointer_get(info[0], &ptr_cpu_context, core);

	GumCpuContext* cpu_context = (GumCpuContext*)ptr_cpu_context;

	GumBacktracer * backtracer = gum_backtracer_make_default();
	GumReturnAddressArray ret_addrs = { 0, };

	gum_backtracer_generate(backtracer, cpu_context, &ret_addrs);

	char* trace = (char*)malloc(MAX_BACKTRACE_STR); trace[0] = NULL;	
	generate_backtrace_string(&ret_addrs, trace);

	info.GetReturnValue().Set(String::NewFromUtf8(info.GetIsolate(), trace));
	free(trace);

}
