/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8core.h"

#include "gumsourcemap.h"
#include "gumv8macros.h"
#include "gumv8scope.h"
#include "gumv8script-priv.h"

#include <ffi.h>
#include <gum/gum-init.h>
#include <string.h>

#define GUMJS_MODULE_NAME Core

using namespace v8;

struct GumV8FlushCallback
{
  GumV8FlushNotify func;
  GumV8Script * script;
};

struct GumV8WeakRef
{
  guint id;
  GumPersistent<Value>::type * target;
  GumPersistent<Function>::type * callback;

  GumV8Core * core;
};

struct GumV8ScheduledCallback
{
  gint id;
  gboolean repeat;
  GumPersistent<Function>::type * func;
  GSource * source;

  GumV8Core * core;
};

struct GumV8ExceptionSink
{
  GumPersistent<Function>::type * callback;
  Isolate * isolate;
};

struct GumV8MessageSink
{
  GumPersistent<Function>::type * callback;
  Isolate * isolate;
};

struct GumV8NativeFunctionParams
{
  GCallback implementation;
  Local<Value> return_type;
  Local<Array> argument_types;
  Local<Value> abi;

  gboolean enable_detailed_return;
};

struct GumV8NativeFunction
{
  GumPersistent<Object>::type * wrapper;

  GCallback implementation;
  gboolean enable_detailed_return;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  GSList * data;

  GumV8Core * core;
};

struct GumV8NativeCallback
{
  GumPersistent<Object>::type * wrapper;

  GumPersistent<Function>::type * func;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
  GSList * data;

  GumV8Core * core;
};

struct GumV8SourceMap
{
  GumPersistent<Object>::type * wrapper;
  GumSourceMap * handle;

  GumV8Core * core;
};

union GumFFIValue
{
  gpointer v_pointer;
  gint v_sint;
  guint v_uint;
  glong v_slong;
  gulong v_ulong;
  gchar v_schar;
  guchar v_uchar;
  gfloat v_float;
  gdouble v_double;
  gint8 v_sint8;
  guint8 v_uint8;
  gint16 v_sint16;
  guint16 v_uint16;
  gint32 v_sint32;
  guint32 v_uint32;
  gint64 v_sint64;
  guint64 v_uint64;
};

struct GumFFITypeMapping
{
  const gchar * name;
  ffi_type * type;
};

struct GumFFIABIMapping
{
  const gchar * name;
  ffi_abi abi;
};

static void gum_v8_core_clear_weak_refs (GumV8Core * self);
static void gum_v8_flush_callback_free (GumV8FlushCallback * self);
static gboolean gum_v8_flush_callback_notify (GumV8FlushCallback * self);

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
static void gum_v8_core_schedule_callback (GumV8Core * self,
    const GumV8Args * args, gboolean repeat);
static void gum_v8_core_add_scheduled_callback (GumV8Core * self,
    GumV8ScheduledCallback * callback);
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
static GumV8ScheduledCallback * gum_v8_scheduled_callback_new (guint id,
    gboolean repeat, GSource * source, GumV8Core * core);
static void gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback);
static gboolean gum_v8_scheduled_callback_invoke (
    GumV8ScheduledCallback * self);
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

static void gumjs_global_get (Local<Name> property,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_global_query (Local<Name> property,
    const PropertyCallbackInfo<Integer> & info);
static void gumjs_global_enumerate (const PropertyCallbackInfo<Array> & info);

GUMJS_DECLARE_GETTER (gumjs_frida_get_source_map)
GUMJS_DECLARE_GETTER (gumjs_frida_objc_get_source_map)
GUMJS_DECLARE_GETTER (gumjs_frida_java_get_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_frida_objc_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_java_load)

GUMJS_DECLARE_GETTER (gumjs_script_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_script_get_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_script_next_tick)
GUMJS_DECLARE_FUNCTION (gumjs_script_pin)
GUMJS_DECLARE_FUNCTION (gumjs_script_unpin)
GUMJS_DECLARE_FUNCTION (gumjs_script_set_global_access_handler)

GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_bind)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_unbind)
static GumV8WeakRef * gum_v8_weak_ref_new (guint id, Handle<Value> target,
    Handle<Function> callback, GumV8Core * core);
static void gum_v8_weak_ref_clear (GumV8WeakRef * ref);
static void gum_v8_weak_ref_free (GumV8WeakRef * ref);
static void gum_v8_weak_ref_on_weak_notify (
    const WeakCallbackInfo<GumV8WeakRef> & info);

GUMJS_DECLARE_FUNCTION (gumjs_int64_construct)
GUMJS_DECLARE_FUNCTION (gumjs_int64_add)
GUMJS_DECLARE_FUNCTION (gumjs_int64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_int64_and)
GUMJS_DECLARE_FUNCTION (gumjs_int64_or)
GUMJS_DECLARE_FUNCTION (gumjs_int64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_int64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_int64_value_of)

GUMJS_DECLARE_FUNCTION (gumjs_uint64_construct)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_add)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_and)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_or)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_value_of)

GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_construct)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_is_null)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_add)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_sub)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_and)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_or)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_xor)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shr)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shl)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_compare)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_int32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_match_pattern)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_call)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_apply)
static gboolean gumjs_native_function_get (
    const FunctionCallbackInfo<Value> & info, Handle<Object> receiver,
    GumV8Core * core, GumV8NativeFunction ** func, GCallback * implementation);
static GumV8NativeFunction * gumjs_native_function_init (Handle<Object> wrapper,
    const GumV8NativeFunctionParams * params, GumV8Core * core);
static void gum_v8_native_function_free (GumV8NativeFunction * self);
static void gum_v8_native_function_invoke (GumV8NativeFunction * self,
    GCallback implementation, const FunctionCallbackInfo<Value> & info,
    uint32_t argc, Handle<Value> * argv);
static void gum_v8_native_function_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeFunction> & info);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_system_function_construct)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
static void gum_v8_native_callback_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeCallback> & info);
static void gum_v8_native_callback_free (GumV8NativeCallback * callback);
static void gum_v8_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cpu_context_construct)
GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_register)
GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_register)

static MaybeLocal<Object> gumjs_source_map_new (const gchar * json,
    GumV8Core * core);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_source_map_construct)
GUMJS_DECLARE_FUNCTION (gumjs_source_map_resolve)
static GumV8SourceMap * gum_v8_source_map_new (Handle<Object> wrapper,
    GumSourceMap * handle, GumV8Core * core);
static void gum_v8_source_map_free (GumV8SourceMap * self);
static void gum_v8_source_map_on_weak_notify (
    const WeakCallbackInfo<GumV8SourceMap> & info);

static GumV8ExceptionSink * gum_v8_exception_sink_new (
    Handle<Function> callback, Isolate * isolate);
static void gum_v8_exception_sink_free (GumV8ExceptionSink * sink);
static void gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
    Handle<Value> exception);

static GumV8MessageSink * gum_v8_message_sink_new (Handle<Function> callback,
    Isolate * isolate);
static void gum_v8_message_sink_free (GumV8MessageSink * sink);
static void gum_v8_message_sink_post (GumV8MessageSink * self,
    const gchar * message, GBytes * data);

static gboolean gum_v8_ffi_type_get (GumV8Core * core, Handle<Value> name,
    ffi_type ** type, GSList ** data);
static gboolean gum_v8_ffi_abi_get (GumV8Core * core, Handle<Value> name,
    ffi_abi * abi);
static gboolean gum_v8_value_to_ffi_type (GumV8Core * core,
    const Handle<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_v8_value_from_ffi_type (GumV8Core * core,
    Handle<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

static const GumV8Function gumjs_global_functions[] =
{
  { "_setTimeout", gumjs_set_timeout, },
  { "_setInterval", gumjs_set_interval },
  { "_clearTimeout", gumjs_clear_timer },
  { "clearInterval", gumjs_clear_timer },
  { "_send", gumjs_send },
  { "_setUnhandledExceptionCallback", gumjs_set_unhandled_exception_callback },
  { "_setIncomingMessageCallback", gumjs_set_incoming_message_callback },
  { "_waitForEvent", gumjs_wait_for_event },

  { NULL, NULL }
};

static const GumV8Property gumjs_frida_values[] =
{
  { "sourceMap", gumjs_frida_get_source_map, NULL },
  { "_objcSourceMap", gumjs_frida_objc_get_source_map, NULL },
  { "_javaSourceMap", gumjs_frida_java_get_source_map, NULL },

  { NULL, NULL }
};

static const GumV8Function gumjs_frida_functions[] =
{
  { "_loadObjC", gumjs_frida_objc_load },
  { "_loadJava", gumjs_frida_java_load },

  { NULL, NULL }
};

static const GumV8Property gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL },
  { "sourceMap", gumjs_script_get_source_map, NULL },

  { NULL, NULL }
};

static const GumV8Function gumjs_script_functions[] =
{
  { "_nextTick", gumjs_script_next_tick },
  { "pin", gumjs_script_pin },
  { "unpin", gumjs_script_unpin },
  { "setGlobalAccessHandler", gumjs_script_set_global_access_handler },

  { NULL, NULL }
};

static const GumV8Function gumjs_weak_ref_functions[] =
{
  { "bind", gumjs_weak_ref_bind },
  { "unbind", gumjs_weak_ref_unbind },

  { NULL, NULL }
};

static const GumV8Function gumjs_int64_functions[] =
{
  { "add", gumjs_int64_add },
  { "sub", gumjs_int64_sub },
  { "and", gumjs_int64_and },
  { "or", gumjs_int64_or },
  { "xor", gumjs_int64_xor },
  { "shr", gumjs_int64_shr },
  { "shl", gumjs_int64_shl },
  { "compare", gumjs_int64_compare },
  { "toNumber", gumjs_int64_to_number },
  { "toString", gumjs_int64_to_string },
  { "toJSON", gumjs_int64_to_json },
  { "valueOf", gumjs_int64_value_of },

  { NULL, NULL }
};

static const GumV8Function gumjs_uint64_functions[] =
{
  { "add", gumjs_uint64_add },
  { "sub", gumjs_uint64_sub },
  { "and", gumjs_uint64_and },
  { "or", gumjs_uint64_or },
  { "xor", gumjs_uint64_xor },
  { "shr", gumjs_uint64_shr },
  { "shl", gumjs_uint64_shl },
  { "compare", gumjs_uint64_compare },
  { "toNumber", gumjs_uint64_to_number },
  { "toString", gumjs_uint64_to_string },
  { "toJSON", gumjs_uint64_to_json },
  { "valueOf", gumjs_uint64_value_of },

  { NULL, NULL }
};

static const GumV8Function gumjs_native_pointer_functions[] =
{
  { "isNull", gumjs_native_pointer_is_null },
  { "add", gumjs_native_pointer_add },
  { "sub", gumjs_native_pointer_sub },
  { "and", gumjs_native_pointer_and },
  { "or", gumjs_native_pointer_or },
  { "xor", gumjs_native_pointer_xor },
  { "shr", gumjs_native_pointer_shr },
  { "shl", gumjs_native_pointer_shl },
  { "compare", gumjs_native_pointer_compare },
  { "toInt32", gumjs_native_pointer_to_int32 },
  { "toString", gumjs_native_pointer_to_string },
  { "toJSON", gumjs_native_pointer_to_json },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern },

  { NULL, NULL }
};

static const GumV8Function gumjs_native_function_functions[] =
{
  { "call", gumjs_native_function_call },
  { "apply", gumjs_native_function_apply },

  { NULL, NULL }
};

static const GumV8Function gumjs_source_map_functions[] =
{
  { "_resolve", gumjs_source_map_resolve },

  { NULL, NULL }
};

void
_gum_v8_core_init (GumV8Core * self,
                   GumV8Script * script,
                   const gchar * runtime_source_map,
                   GumV8MessageEmitter message_emitter,
                   GumScriptScheduler * scheduler,
                   v8::Isolate * isolate,
                   Handle<ObjectTemplate> scope)
{
  self->script = script;
  self->backend = script->priv->backend;
  self->runtime_source_map = runtime_source_map;
  self->core = self;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->isolate = isolate;

  self->usage_count = 0;
  self->flush_notify = NULL;

  self->event_loop = g_main_loop_new (
      gum_script_scheduler_get_js_context (scheduler), FALSE);
  g_mutex_init (&self->event_mutex);
  g_cond_init (&self->event_cond);
  self->event_count = 0;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_weak_ref_free);

  self->tick_callbacks = g_queue_new ();

  auto module = External::New (isolate, self);

  _gum_v8_module_add (module, scope, gumjs_global_functions, isolate);

  NamedPropertyHandlerConfiguration global_access;
  global_access.getter = gumjs_global_get;
  global_access.query = gumjs_global_query;
  global_access.enumerator = gumjs_global_enumerate;
  global_access.data = module;
  global_access.flags = PropertyHandlerFlags::kNonMasking;
  scope->SetHandler (global_access);

  auto frida = _gum_v8_create_module ("Frida", scope, isolate);
  _gum_v8_module_add (module, frida, gumjs_frida_values, isolate);
  _gum_v8_module_add (module, frida, gumjs_frida_functions, isolate);
  frida->Set (_gum_v8_string_new_ascii (isolate, "version"),
      _gum_v8_string_new_ascii (isolate, FRIDA_VERSION), ReadOnly);

  auto script_module = _gum_v8_create_module ("Script", scope, isolate);
  _gum_v8_module_add (module, script_module, gumjs_script_values, isolate);
  _gum_v8_module_add (module, script_module, gumjs_script_functions, isolate);
  script_module->Set (_gum_v8_string_new_ascii (isolate, "runtime"),
      _gum_v8_string_new_ascii (isolate, "V8"), ReadOnly);

  auto weak = _gum_v8_create_module ("WeakRef", scope, isolate);
  _gum_v8_module_add (module, weak, gumjs_weak_ref_functions, isolate);

  auto int64 = _gum_v8_create_class ("Int64", gumjs_int64_construct, scope,
      module, isolate);
  _gum_v8_class_add (int64, gumjs_int64_functions, module, isolate);
  int64->InstanceTemplate ()->SetInternalFieldCount (8 / GLIB_SIZEOF_VOID_P);
  self->int64 = new GumPersistent<FunctionTemplate>::type (isolate, int64);

  auto uint64 = _gum_v8_create_class ("UInt64", gumjs_uint64_construct, scope,
      module, isolate);
  _gum_v8_class_add (uint64, gumjs_uint64_functions, module, isolate);
  uint64->InstanceTemplate ()->SetInternalFieldCount (8 / GLIB_SIZEOF_VOID_P);
  self->uint64 = new GumPersistent<FunctionTemplate>::type (isolate, uint64);

  auto native_pointer = _gum_v8_create_class ("NativePointer",
      gumjs_native_pointer_construct, scope, module, isolate);
  _gum_v8_class_add (native_pointer, gumjs_native_pointer_functions, module,
      isolate);
  self->native_pointer =
      new GumPersistent<FunctionTemplate>::type (isolate, native_pointer);

  auto native_function = _gum_v8_create_class ("NativeFunction",
      gumjs_native_function_construct, scope, module, isolate);
  native_function->Inherit (native_pointer);
  _gum_v8_class_add (native_function, gumjs_native_function_functions, module,
      isolate);
  auto native_function_object = native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gumjs_native_function_invoke, module);
  native_function_object->SetInternalFieldCount (2);
  self->native_function =
      new GumPersistent<FunctionTemplate>::type (isolate, native_function);

  auto system_function = _gum_v8_create_class ("SystemFunction",
      gumjs_system_function_construct, scope, module, isolate);
  system_function->Inherit (native_function);
  auto system_function_object = system_function->InstanceTemplate ();
  system_function_object->SetCallAsFunctionHandler (
      gumjs_native_function_invoke, module);
  system_function_object->SetInternalFieldCount (2);

  auto native_callback = _gum_v8_create_class ("NativeCallback",
      gumjs_native_callback_construct, scope, module, isolate);
  native_callback->Inherit (native_pointer);
  native_callback->InstanceTemplate ()->SetInternalFieldCount (1);

  auto cpu_context = _gum_v8_create_class ("CpuContext",
      gumjs_cpu_context_construct, scope, module, isolate);
  auto cpu_context_object = cpu_context->InstanceTemplate ();
  cpu_context_object->SetInternalFieldCount (3);
  auto cpu_context_signature = AccessorSignature::New (isolate, cpu_context);
  self->cpu_context =
      new GumPersistent<FunctionTemplate>::type (isolate, cpu_context);

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  cpu_context_object->SetAccessor ( \
      _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
      gumjs_cpu_context_get_register, \
      gumjs_cpu_context_set_register, \
      Integer::NewFromUnsigned (isolate, \
          G_STRUCT_OFFSET (GumCpuContext, R) / GLIB_SIZEOF_VOID_P), \
      DEFAULT, \
      DontDelete, \
      cpu_context_signature)
#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR(R) \
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (pc, eip);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (sp, esp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (eax);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (ecx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (edx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (ebx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (esp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (ebp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (esi);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (edi);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (eip);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (pc, rip);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (sp, rsp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rax);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rcx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rdx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rbx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rsp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rbp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rsi);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rdi);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r8);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r9);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r10);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r11);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r12);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r13);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r14);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r15);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (rip);
#elif defined (HAVE_ARM)
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (pc);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (sp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r0, r[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r1, r[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r2, r[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r3, r[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r4, r[4]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r5, r[5]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r6, r[6]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r7, r[7]);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r8);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r9);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r10);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r11);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (r12);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (lr);
#elif defined (HAVE_ARM64)
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (pc);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (sp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x0, x[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x1, x[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x2, x[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x3, x[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x4, x[4]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x5, x[5]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x6, x[6]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x7, x[7]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x8, x[8]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x9, x[9]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x10, x[10]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x11, x[11]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x12, x[12]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x13, x[13]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x14, x[14]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x15, x[15]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x16, x[16]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x17, x[17]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x18, x[18]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x19, x[19]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x20, x[20]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x21, x[21]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x22, x[22]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x23, x[23]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x24, x[24]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x25, x[25]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x26, x[26]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x27, x[27]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x28, x[28]);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (fp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR (lr);
#endif

  auto source_map = _gum_v8_create_class ("SourceMap",
      gumjs_source_map_construct, scope, module, isolate);
  _gum_v8_class_add (source_map, gumjs_source_map_functions, module, isolate);
  self->source_map =
      new GumPersistent<FunctionTemplate>::type (isolate, source_map);
}

void
_gum_v8_core_realize (GumV8Core * self)
{
  auto isolate = self->isolate;
  auto context = isolate->GetCurrentContext ();

  auto global = context->Global ();
  global->Set (_gum_v8_string_new_ascii (isolate, "global"), global);

  self->native_functions = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_native_function_free);

  self->native_callbacks = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_native_callback_free);

  self->native_resources = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) _gum_v8_native_resource_free);

  self->source_maps = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_source_map_free);

  Local<Value> zero = Integer::New (isolate, 0);

  auto int64 = Local<FunctionTemplate>::New (isolate, *self->int64);
  auto int64_value =
      int64->GetFunction ()->NewInstance (context, 1, &zero).ToLocalChecked ();
  self->int64_value = new GumPersistent<Object>::type (isolate, int64_value);

  auto uint64 = Local<FunctionTemplate>::New (isolate, *self->uint64);
  auto uint64_value = uint64->GetFunction ()->NewInstance (context, 1, &zero)
      .ToLocalChecked ();
  self->uint64_value = new GumPersistent<Object>::type (isolate, uint64_value);

  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *self->native_pointer);
  auto native_pointer_value = native_pointer->GetFunction ()->NewInstance (
      context, 1, &zero).ToLocalChecked ();
  self->native_pointer_value = new GumPersistent<Object>::type (isolate,
      native_pointer_value);
  self->handle_key = new GumPersistent<String>::type (isolate,
      _gum_v8_string_new_ascii (isolate, "handle"));

  auto value_key = _gum_v8_string_new_ascii (isolate, "value");
  self->value_key = new GumPersistent<String>::type (isolate, value_key);
  auto system_error_key =
      _gum_v8_string_new_ascii (isolate, GUMJS_SYSTEM_ERROR_FIELD);
  self->system_error_key = new GumPersistent<String>::type (isolate,
      system_error_key);

  auto native_return_value = Object::New (isolate);
  native_return_value->Set (context, value_key, zero).FromJust ();
  native_return_value->Set (context, system_error_key, zero).FromJust ();
  self->native_return_value = new GumPersistent<Object>::type (isolate,
      native_return_value);

  auto cpu_context = Local<FunctionTemplate>::New (isolate, *self->cpu_context);
  Local<Value> args[] = {
    External::New (isolate, NULL),
    Boolean::New (isolate, false)
  };
  auto cpu_context_value = cpu_context->GetFunction ()->NewInstance (context,
      G_N_ELEMENTS (args), args).ToLocalChecked ();
  self->cpu_context_value = new GumPersistent<Object>::type (isolate,
      cpu_context_value);
}

gboolean
_gum_v8_core_flush (GumV8Core * self,
                    GumV8FlushNotify flush_notify)
{
  gboolean done;

  self->flush_notify = flush_notify;

  if (self->usage_count > 1)
    return FALSE;

  while (self->scheduled_callbacks != NULL)
  {
    auto callback = (GumV8ScheduledCallback *) self->scheduled_callbacks->data;

    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);

    auto source = g_source_ref (callback->source);

    _gum_v8_core_pin (self);

    self->isolate->Exit ();
    {
      Unlocker ul (self->isolate);

      g_source_destroy (source);
      g_source_unref (source);
    }
    self->isolate->Enter ();
  }

  if (self->usage_count > 1)
    return FALSE;

  gum_v8_core_clear_weak_refs (self);

  done = self->usage_count == 1;
  if (done)
    self->flush_notify = NULL;

  return done;
}

static void
gum_v8_core_clear_weak_refs (GumV8Core * self)
{
  GHashTableIter iter;
  GumV8WeakRef * ref;

  g_hash_table_iter_init (&iter, self->weak_refs);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &ref))
  {
    gum_v8_weak_ref_clear (ref);
  }

  g_hash_table_remove_all (self->weak_refs);
}

void
_gum_v8_core_notify_flushed (GumV8Core * self,
                             GumV8FlushNotify func)
{
  auto callback = g_slice_new (GumV8FlushCallback);
  callback->func = func;
  callback->script = GUM_V8_SCRIPT_CAST (g_object_ref (self->script));

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_flush_callback_notify,
      callback, (GDestroyNotify) gum_v8_flush_callback_free);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  g_source_unref (source);
}

static void
gum_v8_flush_callback_free (GumV8FlushCallback * self)
{
  g_object_unref (self->script);

  g_slice_free (GumV8FlushCallback, self);
}

static gboolean
gum_v8_flush_callback_notify (GumV8FlushCallback * self)
{
  self->func (self->script);
  return FALSE;
}

void
_gum_v8_core_dispose (GumV8Core * self)
{
  g_hash_table_unref (self->source_maps);
  self->source_maps = NULL;

  g_hash_table_unref (self->native_resources);
  self->native_resources = NULL;

  g_hash_table_unref (self->native_callbacks);
  self->native_callbacks = NULL;

  g_hash_table_unref (self->native_functions);
  self->native_functions = NULL;

  g_clear_pointer (&self->unhandled_exception_sink, gum_v8_exception_sink_free);

  g_clear_pointer (&self->incoming_message_sink, gum_v8_message_sink_free);

  delete self->on_global_enumerate;
  delete self->on_global_get;
  delete self->global_receiver;
  self->on_global_enumerate = nullptr;
  self->on_global_get = nullptr;
  self->global_receiver = nullptr;

  delete self->int64_value;
  self->int64_value = nullptr;

  delete self->uint64_value;
  self->uint64_value = nullptr;

  delete self->handle_key;
  delete self->native_pointer_value;
  self->handle_key = nullptr;
  self->native_pointer_value = nullptr;

  delete self->value_key;
  delete self->system_error_key;
  self->value_key = nullptr;
  self->system_error_key = nullptr;

  delete self->native_return_value;
  self->native_return_value = nullptr;

  delete self->cpu_context_value;
  self->cpu_context_value = nullptr;
}

void
_gum_v8_core_finalize (GumV8Core * self)
{
  g_assert (g_queue_is_empty (self->tick_callbacks));
  g_queue_free (self->tick_callbacks);
  self->tick_callbacks = NULL;

  g_hash_table_unref (self->weak_refs);
  self->weak_refs = NULL;

  delete self->source_map;
  self->source_map = nullptr;

  delete self->cpu_context;
  self->cpu_context = nullptr;

  delete self->native_function;
  self->native_function = nullptr;

  delete self->native_pointer;
  self->native_pointer = nullptr;

  delete self->uint64;
  self->uint64 = nullptr;

  delete self->int64;
  self->int64 = nullptr;

  g_object_unref (self->exceptor);
  self->exceptor = NULL;

  g_main_loop_unref (self->event_loop);
  self->event_loop = NULL;
  g_mutex_clear (&self->event_mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_v8_core_pin (GumV8Core * self)
{
  self->usage_count++;
}

void
_gum_v8_core_unpin (GumV8Core * self)
{
  self->usage_count--;
}

void
_gum_v8_core_on_unhandled_exception (GumV8Core * self,
                                     Handle<Value> exception)
{
  if (self->unhandled_exception_sink == NULL)
    return;

  gum_v8_exception_sink_handle_exception (self->unhandled_exception_sink,
      exception);
}

void
_gum_v8_core_post (GumV8Core * self,
                   const gchar * message,
                   GBytes * data)
{
  gboolean delivered = FALSE;

  {
    Locker locker (self->isolate);

    if (self->incoming_message_sink != NULL)
    {
      ScriptScope scope (self->script);
      gum_v8_message_sink_post (self->incoming_message_sink, message, data);
      delivered = TRUE;
    }
  }

  if (delivered)
  {
    g_mutex_lock (&self->event_mutex);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    g_mutex_unlock (&self->event_mutex);

    g_main_loop_quit (self->event_loop);
  }
  else
  {
    g_bytes_unref (data);
  }
}

/*
 * Prototype:
 * setTimeout(callback, delay)
 *
 * Docs:
 * Calls a function or executes a code snippet after a specified delay.
 *
 * Example:
 * // Delay for 3 seconds, then log to console
 * -> setTimeout(function(){console.log("Fired!")}, 3000)
 */
GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  gum_v8_core_schedule_callback (core, args, FALSE);
}

/*
 * Prototype:
 * setInterval(callback, delay)
 *
 * Docs:
 * Calls a function or executes a code snippet repeatedly, with a fixed
 * time delay between each call to that function. Returns an intervalID.
 *
 * Example:
 * // Every 3 seconds, log to console
 * -> setInterval(function(){console.log("Fired!")}, 3000)
 */
GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  gum_v8_core_schedule_callback (core, args, TRUE);
}

static void
gum_v8_core_schedule_callback (GumV8Core * self,
                               const GumV8Args * args,
                               gboolean repeat)
{
  Local<Function> func;
  gsize delay;

  if (repeat)
  {
    if (!_gum_v8_args_parse (args, "FZ", &func, &delay))
      return;
  }
  else
  {
    delay = 0;
    if (!_gum_v8_args_parse (args, "F|Z", &func, &delay))
      return;
  }

  auto id = ++self->last_callback_id;
  GSource * source;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);
  auto callback = gum_v8_scheduled_callback_new (id, repeat, source, self);
  callback->func = new GumPersistent<Function>::type (self->isolate, func);
  g_source_set_callback (source, (GSourceFunc) gum_v8_scheduled_callback_invoke,
      callback, (GDestroyNotify) gum_v8_scheduled_callback_free);
  gum_v8_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));

  args->info->GetReturnValue ().Set (id);
}

static void
gum_v8_core_add_scheduled_callback (GumV8Core * self,
                                    GumV8ScheduledCallback * callback)
{
  self->scheduled_callbacks =
      g_slist_prepend (self->scheduled_callbacks, callback);
}

static gboolean
gum_v8_core_remove_scheduled_callback (GumV8Core * self,
                                       GumV8ScheduledCallback * callback)
{
  auto link = g_slist_find (self->scheduled_callbacks, callback);
  if (link == NULL)
    return FALSE;

  self->scheduled_callbacks =
      g_slist_delete_link (self->scheduled_callbacks, link);
  return TRUE;
}

/*
 * Prototype:
 * clearTimeout(id)/clearInterval(id)
 *
 * Docs:
 * Clears the delay set by setTimeout/setInterval
 *
 * Example:
 * // Create a timeout, and abort immediately
 * -> var test = setTimeout(function(){console.log("Fired!")}, 3000);
 * -> clearTimeout(test)
 */
GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  gint id;
  if (!_gum_v8_args_parse (args, "i", &id))
    return;

  GumV8ScheduledCallback * callback = NULL;
  for (auto cur = core->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    auto cb = (GumV8ScheduledCallback *) cur->data;
    if (cb->id == id)
    {
      callback = cb;
      core->scheduled_callbacks =
          g_slist_delete_link (core->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
  {
    auto source = g_source_ref (callback->source);

    _gum_v8_core_pin (core);

    core->isolate->Exit ();
    {
      Unlocker ul (core->isolate);

      g_source_destroy (source);
      g_source_unref (source);
    }
    core->isolate->Enter ();
  }

  info.GetReturnValue ().Set (callback != NULL);
}

static GumV8ScheduledCallback *
gum_v8_scheduled_callback_new (guint id,
                               gboolean repeat,
                               GSource * source,
                               GumV8Core * core)
{
  auto callback = g_slice_new (GumV8ScheduledCallback);

  callback->id = id;
  callback->repeat = repeat;
  callback->source = source;

  callback->core = core;

  return callback;
}

static void
gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback)
{
  auto core = callback->core;

  {
    ScriptScope scope (core->script);

    delete callback->func;

    _gum_v8_core_unpin (core);
  }

  g_source_unref (callback->source);

  g_slice_free (GumV8ScheduledCallback, callback);
}

static gboolean
gum_v8_scheduled_callback_invoke (GumV8ScheduledCallback * self)
{
  auto core = self->core;

  ScriptScope scope (core->script);
  auto func = Local<Function>::New (core->isolate, *self->func);
  func->Call (Undefined (core->isolate), 0, nullptr);

  if (!self->repeat)
  {
    if (gum_v8_core_remove_scheduled_callback (core, self))
      _gum_v8_core_pin (core);
  }

  return self->repeat;
}

/*
 * Prototype:
 * [PRIVATE] _send(message[, array=null])
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  gchar * message;
  GBytes * data;
  if (!_gum_v8_args_parse (args, "sB?", &message, &data))
    return;

  /*
   * Synchronize Interceptor state before sending the message. The application
   * might be waiting for an acknowledgement that APIs have been instrumented.
   *
   * This is very important for the RPC API.
   */
  auto interceptor = core->script->priv->interceptor.interceptor;
  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  core->message_emitter (core->script, message, data);

  g_bytes_unref (data);
  g_free (message);
}

/*
 * Prototype:
 * _setUnhandledExceptionCallback(callback)
 *
 * Docs:
 * [PRIVATE] Set callback to fire when an unhandled exception occurs
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_sink = !callback.IsEmpty ()
      ? gum_v8_exception_sink_new (callback, isolate)
      : NULL;

  auto old_sink = core->unhandled_exception_sink;
  core->unhandled_exception_sink = new_sink;

  if (old_sink != NULL)
    gum_v8_exception_sink_free (old_sink);
}

/*
 * Prototype:
 * _setIncomingMessageCallback(callback)
 *
 * Docs:
 * [PRIVATE] Set callback to fire when a message is received
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_sink = !callback.IsEmpty ()
      ? gum_v8_message_sink_new (callback, isolate)
      : NULL;

  auto old_sink = core->incoming_message_sink;
  core->incoming_message_sink = new_sink;

  if (old_sink != NULL)
    gum_v8_message_sink_free (old_sink);
}

/*
 * Prototype:
 * [PRIVATE] _waitForEvent(argument1)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  core->isolate->Exit ();
  {
    Unlocker ul (core->isolate);

    auto context = gum_script_scheduler_get_js_context (core->scheduler);
    if (g_main_context_is_owner (context))
    {
      g_mutex_lock (&core->event_mutex);
      auto start_count = core->event_count;
      while (core->event_count == start_count)
      {
        g_mutex_unlock (&core->event_mutex);
        g_main_loop_run (core->event_loop);
        g_mutex_lock (&core->event_mutex);
      }
      g_mutex_unlock (&core->event_mutex);
    }
    else
    {
      g_mutex_lock (&core->event_mutex);
      auto start_count = core->event_count;
      while (core->event_count == start_count)
        g_cond_wait (&core->event_cond, &core->event_mutex);
      g_mutex_unlock (&core->event_mutex);
    }
  }
  core->isolate->Enter ();
}

static void
gumjs_global_get (Local<Name> property,
                  const PropertyCallbackInfo<Value> & info)
{
  auto self = (GumV8Core *) info.Data ().As<External> ()->Value ();

  if (self->on_global_get == nullptr)
    return;

  auto isolate = info.GetIsolate ();

  auto get (Local<Function>::New (isolate, *self->on_global_get));
  auto receiver (Local<Object>::New (isolate, *self->global_receiver));
  Handle<Value> argv[] = { property };
  auto result = get->Call (receiver, G_N_ELEMENTS (argv), argv);
  if (!result.IsEmpty () && !result->IsUndefined ())
  {
    info.GetReturnValue ().Set (result);
  }
}

static void
gumjs_global_query (Local<Name> property,
                    const PropertyCallbackInfo<Integer> & info)
{
  auto self = (GumV8Core *) info.Data ().As<External> ()->Value ();

  if (self->on_global_get == nullptr)
    return;

  auto isolate = info.GetIsolate ();

  auto get (Local<Function>::New (isolate, *self->on_global_get));
  auto receiver (Local<Object>::New (isolate, *self->global_receiver));
  Handle<Value> argv[] = { property };
  auto result = get->Call (receiver, G_N_ELEMENTS (argv), argv);
  if (!result.IsEmpty () && !result->IsUndefined ())
  {
    info.GetReturnValue ().Set (PropertyAttribute::ReadOnly |
        PropertyAttribute::DontDelete);
  }
}

static void
gumjs_global_enumerate (const PropertyCallbackInfo<Array> & info)
{
  auto self = (GumV8Core *) info.Data ().As<External> ()->Value ();

  if (self->on_global_enumerate == nullptr)
    return;

  auto isolate = info.GetIsolate ();

  auto enumerate (Local<Function>::New (isolate, *self->on_global_enumerate));
  auto receiver (Local<Object>::New (isolate, *self->global_receiver));
  auto result = enumerate->Call (receiver, 0, nullptr);
  if (!result.IsEmpty () && result->IsArray ())
  {
    info.GetReturnValue ().Set (result.As<Array> ());
  }
}

GUMJS_DEFINE_GETTER (gumjs_frida_get_source_map)
{
  Local<Object> map;
  if (gumjs_source_map_new (core->runtime_source_map, core).ToLocal (&map))
    info.GetReturnValue ().Set (map);
}

GUMJS_DEFINE_GETTER (gumjs_frida_objc_get_source_map)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (
      core->script->priv->backend);

  Local<Object> map;
  if (gumjs_source_map_new (platform->GetObjCSourceMap (), core).ToLocal (&map))
    info.GetReturnValue ().Set (map);
}

GUMJS_DEFINE_GETTER (gumjs_frida_java_get_source_map)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (
      core->script->priv->backend);

  Local<Object> map;
  if (gumjs_source_map_new (platform->GetJavaSourceMap (), core).ToLocal (&map))
    info.GetReturnValue ().Set (map);
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_objc_load)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (
      core->script->priv->backend);

  gum_v8_bundle_run (platform->GetObjCBundle ());
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_java_load)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (
      core->script->priv->backend);

  gum_v8_bundle_run (platform->GetJavaBundle ());
}

GUMJS_DEFINE_GETTER (gumjs_script_get_file_name)
{
  Local<Value> result;

  auto priv = core->script->priv;
  if (priv->code != nullptr)
  {
    auto code = Local<Script>::New (isolate, *priv->code);
    auto file_name = code->GetUnboundScript ()->GetScriptName ();
    if (file_name->IsString ())
      result = file_name;
  }

  if (!result.IsEmpty ())
    info.GetReturnValue ().Set (result);
  else
    info.GetReturnValue ().SetNull ();
}

GUMJS_DEFINE_GETTER (gumjs_script_get_source_map)
{
  gchar * json = NULL;

  auto priv = core->script->priv;
  if (priv->code != nullptr)
  {
    auto code = Local<Script>::New (isolate, *priv->code);

    auto url_value = code->GetUnboundScript ()->GetSourceMappingURL ();
    if (url_value->IsString ())
    {
      String::Utf8Value url_utf8 (url_value);
      auto url = *url_utf8;

      auto base64_start = strstr (url, "base64,");

      if (g_str_has_prefix (url, "data:application/json;") &&
          base64_start != NULL)
      {
        base64_start += 7;

        gsize size;
        auto data = (gchar *) g_base64_decode (base64_start, &size);
        if (data != NULL && g_utf8_validate (data, size, NULL))
          json = data;
        else
          g_free (data);
      }
    }
  }

  if (json != NULL)
  {
    Local<Object> map;
    if (gumjs_source_map_new (json, core).ToLocal (&map))
      info.GetReturnValue ().Set (map);
    g_free (json);
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_script_next_tick)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  g_queue_push_tail (core->tick_callbacks, new GumPersistent<Function>::type (
      isolate, callback));
}

GUMJS_DEFINE_FUNCTION (gumjs_script_pin)
{
  _gum_v8_core_pin (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unpin)
{
  _gum_v8_core_unpin (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_set_global_access_handler)
{
  Local<Function> on_enumerate, on_get;
  Local<Object> callbacks;
  gboolean has_callbacks = !(info.Length () > 0 && info[0]->IsNull ());
  if (has_callbacks)
  {
    if (!_gum_v8_args_parse (args, "F{enumerate,get}", &on_enumerate, &on_get))
      return;
    callbacks = info[0].As<Object> ();
  }

  delete core->on_global_enumerate;
  delete core->on_global_get;
  delete core->global_receiver;
  core->on_global_enumerate = nullptr;
  core->on_global_get = nullptr;
  core->global_receiver = nullptr;

  if (has_callbacks)
  {
    core->on_global_enumerate = new GumPersistent<Function>::type (isolate,
        on_enumerate.As<Function> ());
    core->on_global_get = new GumPersistent<Function>::type (isolate,
        on_get.As<Function> ());
    core->global_receiver = new GumPersistent<Object>::type (isolate,
        callbacks);
  }
}

/*
 * Prototype:
 * WeakRef.bind(target, callback_val)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_bind)
{
  Local<Value> target;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "VF", &target, &callback))
    return;

  if (target->IsUndefined () || target->IsNull ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a heap value");
    return;
  }

  auto id = ++core->last_weak_ref_id;

  auto ref = gum_v8_weak_ref_new (id, target, callback, core);
  g_hash_table_insert (core->weak_refs, GUINT_TO_POINTER (id), ref);

  info.GetReturnValue ().Set (id);
}

/*
 * Prototype:
 * WeakRef.unbind(id_val)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_unbind)
{
  guint id;
  if (!_gum_v8_args_parse (args, "u", &id))
    return;

  bool removed = !!g_hash_table_remove (core->weak_refs, GUINT_TO_POINTER (id));
  info.GetReturnValue ().Set (removed);
}

static GumV8WeakRef *
gum_v8_weak_ref_new (guint id,
                     Handle<Value> target,
                     Handle<Function> callback,
                     GumV8Core * core)
{
  auto ref = g_slice_new (GumV8WeakRef);

  ref->id = id;
  ref->target = new GumPersistent<Value>::type (core->isolate, target);
  ref->target->SetWeak (ref, gum_v8_weak_ref_on_weak_notify,
      WeakCallbackType::kParameter);
  ref->target->MarkIndependent ();
  ref->callback = new GumPersistent<Function>::type (core->isolate, callback);

  ref->core = core;

  return ref;
}

static void
gum_v8_weak_ref_clear (GumV8WeakRef * ref)
{
  delete ref->target;
  ref->target = nullptr;
}

static void
gum_v8_weak_ref_free (GumV8WeakRef * ref)
{
  gum_v8_weak_ref_clear (ref);

  {
    ScriptScope scope (ref->core->script);
    auto isolate = ref->core->isolate;
    auto callback = Local<Function>::New (isolate, *ref->callback);
    callback->Call (Undefined (isolate), 0, nullptr);
  }
  delete ref->callback;

  g_slice_free (GumV8WeakRef, ref);
}

static void
gum_v8_weak_ref_on_weak_notify (const WeakCallbackInfo<GumV8WeakRef> & info)
{
  auto self = info.GetParameter ();

  g_hash_table_remove (self->core->weak_refs, GUINT_TO_POINTER (self->id));
}

void
_gum_v8_core_push_job (GumV8Core * self,
                       GumScriptJobFunc job_func,
                       gpointer data,
                       GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_int64_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new Int64()` to create a new "
        "instance, or use the shorthand: `int64()`");
    return;
  }

  gint64 value;
  if (!_gum_v8_args_parse (args, "q~", &value))
    return;

  _gum_v8_int64_set_value (wrapper, value, isolate);
}

#define GUM_DEFINE_INT64_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
  { \
    gint64 lhs = _gum_v8_int64_get_value (info.Holder ()); \
    \
    gint64 rhs; \
    if (!_gum_v8_args_parse (args, "q~", &rhs)) \
      return; \
    \
    gint64 result = lhs op rhs; \
    \
    info.GetReturnValue ().Set (_gum_v8_int64_new (result, core)); \
  }

GUM_DEFINE_INT64_OP_IMPL (add, +)
GUM_DEFINE_INT64_OP_IMPL (sub, -)
GUM_DEFINE_INT64_OP_IMPL (and, &)
GUM_DEFINE_INT64_OP_IMPL (or,  |)
GUM_DEFINE_INT64_OP_IMPL (xor, ^)
GUM_DEFINE_INT64_OP_IMPL (shr, >>)
GUM_DEFINE_INT64_OP_IMPL (shl, <<)

/*
 * Prototype:
 * Int64.compare(that)
 *
 * Docs:
 * Returns 0 if this and that are equal.
 * Otherwise returns -1 if this < that and 1 if this > that
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_int64_compare)
{
  gint64 lhs = _gum_v8_int64_get_value (info.Holder ());

  gint64 rhs;
  if (!_gum_v8_args_parse (args, "q~", &rhs))
    return;

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

/*
 * Prototype:
 * Int64.toNumber()
 *
 * Docs:
 * Represents the value as a JavaScript Number
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_int64_to_number)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_int64_get_value (info.Holder ()));
}

/*
 * Prototype:
 * Int64.toString([radix=10])
 *
 * Docs:
 * Represents the value as either a base-10 or base-16 string.
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_int64_to_string)
{
  gint radix = 10;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  auto value = _gum_v8_int64_get_value (info.Holder ());

  gchar str[32];
  if (radix == 10)
    sprintf (str, "%" G_GINT64_FORMAT, value);
  else if (value >= 0)
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);
  else
    sprintf (str, "-%" G_GINT64_MODIFIER "x", -value);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * Int64.toJSON()
 *
 * Docs:
 * Represents the value as a JSON-formatted value
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_int64_to_json)
{
  gchar str[32];
  sprintf (str, "%" G_GINT64_FORMAT, _gum_v8_int64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * Int64.valueOf()
 *
 * Docs:
 * Represents the value as a JavaScript Number
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_int64_value_of)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_int64_get_value (info.Holder ()));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_uint64_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new UInt64()` to create a new "
        "instance, or use the shorthand: `uint64()`");
    return;
  }

  guint64 value;
  if (!_gum_v8_args_parse (args, "Q~", &value))
    return;

  _gum_v8_uint64_set_value (wrapper, value, isolate);
}

#define GUM_DEFINE_UINT64_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
  { \
    guint64 lhs = _gum_v8_uint64_get_value (info.Holder ()); \
    \
    guint64 rhs; \
    if (!_gum_v8_args_parse (args, "Q~", &rhs)) \
      return; \
    \
    guint64 result = lhs op rhs; \
    \
    info.GetReturnValue ().Set (_gum_v8_uint64_new (result, core)); \
  }

GUM_DEFINE_UINT64_OP_IMPL (add, +)
GUM_DEFINE_UINT64_OP_IMPL (sub, -)
GUM_DEFINE_UINT64_OP_IMPL (and, &)
GUM_DEFINE_UINT64_OP_IMPL (or,  |)
GUM_DEFINE_UINT64_OP_IMPL (xor, ^)
GUM_DEFINE_UINT64_OP_IMPL (shr, >>)
GUM_DEFINE_UINT64_OP_IMPL (shl, <<)

/*
 * Prototype:
 * UInt64.compare(that)
 *
 * Docs:
 * Returns 0 if this and that are equal.
 * Otherwise returns -1 if this < that and 1 if this > that
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_uint64_compare)
{
  guint64 lhs = _gum_v8_uint64_get_value (info.Holder ());

  guint64 rhs;
  if (!_gum_v8_args_parse (args, "Q~", &rhs))
    return;

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

/*
 * Prototype:
 * UInt64.toNumber()
 *
 * Docs:
 * Represents the value as a JavaScript Number
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_number)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_uint64_get_value (info.Holder ()));
}

/*
 * Prototype:
 * UInt64.toString([radix=10])
 *
 * Docs:
 * Represents the value as either a base-10 or base-16 string.
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_string)
{
  gint radix = 10;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  auto value = _gum_v8_uint64_get_value (info.Holder ());

  gchar str[32];
  if (radix == 10)
    sprintf (str, "%" G_GUINT64_FORMAT, value);
  else
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * UInt64.toJSON()
 *
 * Docs:
 * Represents the value as a JSON-formatted value
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_json)
{
  gchar str[32];
  sprintf (str, "%" G_GUINT64_FORMAT,
      _gum_v8_uint64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * UInt64.valueOf()
 *
 * Docs:
 * Represents the value as a JavaScript Number
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_uint64_value_of)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_uint64_get_value (info.Holder ()));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new NativePointer()` to "
        "create a new instance, or use one of the two shorthands: "
        "`ptr()` and `NULL`");
    return;
  }

  gpointer ptr;
  if (!_gum_v8_args_parse (args, "p~", &ptr))
    return;

  wrapper->SetInternalField (0, External::New (isolate, ptr));
}

/*
 * Prototype:
 * NativePointer.isNull()
 *
 * Docs:
 * Returns true if a pointer is NULL, otherwise false
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  info.GetReturnValue ().Set (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()) == 0);
}

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
  { \
    gpointer lhs_ptr = GUMJS_NATIVE_POINTER_VALUE (info.Holder ()); \
    \
    gpointer rhs_ptr; \
    if (!_gum_v8_args_parse (args, "p~", &rhs_ptr)) \
      return; \
    \
    gsize lhs = GPOINTER_TO_SIZE (lhs_ptr); \
    gsize rhs = GPOINTER_TO_SIZE (rhs_ptr); \
    \
    gpointer result = GSIZE_TO_POINTER (lhs op rhs); \
    \
    info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, core)); \
  }

GUM_DEFINE_NATIVE_POINTER_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (shl, <<)

/*
 * Prototype:
 * NativePointer.compare(that)
 *
 * Docs:
 * Returns 0 if this and that are equal.
 * Otherwise returns -1 if this < that and 1 if this > that
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  gpointer lhs_ptr = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  gpointer rhs_ptr;
  if (!_gum_v8_args_parse (args, "p~", &rhs_ptr))
    return;

  gsize lhs = GPOINTER_TO_SIZE (lhs_ptr);
  gsize rhs = GPOINTER_TO_SIZE (rhs_ptr);

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

/*
 * Prototype:
 * NativePointer.toInt32()
 *
 * Docs:
 * Represents the pointer as a signed 32-bit integer
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  info.GetReturnValue ().Set ((int32_t) GPOINTER_TO_SIZE (
      GUMJS_NATIVE_POINTER_VALUE (info.Holder ())));
}

/*
 * Prototype:
 * NativePointer.toString([radix=16])
 *
 * Docs:
 * Represents the pointer as either a base-10 or base-16 string.
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  gint radix = 0;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  gboolean radix_specified = radix != 0;
  if (!radix_specified)
  {
    radix = 16;
  }
  else if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar str[32];
  if (radix == 10)
  {
    sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr);
  }
  else
  {
    if (radix_specified)
      sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr);
    else
      sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);
  }

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * NativePointer.toJSON()
 *
 * Docs:
 * Represents the pointer as a JSON-formatted value
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar str[32];
  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

/*
 * Prototype:
 * NativePointer.toMatchPattern()
 *
 * Docs:
 * Represents the pointer as a pattern.
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  gchar result[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      result[dst++] = ' ';
    result[dst++] = nibble_to_char[(ptr >> (src + 4)) & 0xf];
    result[dst++] = nibble_to_char[(ptr >> (src + 0)) & 0xf];
  }
  result[dst] = '\0';

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, result));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new NativeFunction()` to create a new instance");
    return;
  }

  GumV8NativeFunctionParams params;

  if (!_gum_v8_args_parse (args, "pVA|V", &params.implementation,
      &params.return_type, &params.argument_types, &params.abi))
    return;

  params.enable_detailed_return = FALSE;

  gumjs_native_function_init (wrapper, &params, core);
}

static void
gumjs_native_function_invoke (const FunctionCallbackInfo<Value> & info)
{
  auto self = (GumV8NativeFunction *)
      info.Holder ()->GetAlignedPointerFromInternalField (1);

  gum_v8_native_function_invoke (self, self->implementation, info, 0, nullptr);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_call)
{
  Local<Object> receiver;
  if (!_gum_v8_args_parse (args, "O?", &receiver))
    return;

  GumV8NativeFunction * func;
  GCallback implementation;
  if (!gumjs_native_function_get (info, receiver, core, &func, &implementation))
    return;

  uint32_t argc = info.Length () - 1;

  Local<Value> * argv = nullptr;
  if (argc > 0)
  {
    argv = (Local<Value> *) g_alloca (argc * sizeof (Local<Value>));
    for (uint32_t i = 0; i != argc; i++)
    {
      new (&argv[i]) Local<Value> ();
      argv[i] = info[1 + i];
    }
  }

  gum_v8_native_function_invoke (func, implementation, info, argc, argv);

  for (uint32_t i = 0; i != argc; i++)
    argv[i].~Local<Value> ();
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_apply)
{
  Local<Object> receiver;
  Local<Array> argv_array;
  if (!_gum_v8_args_parse (args, "O?A", &receiver, &argv_array))
    return;

  GumV8NativeFunction * func;
  GCallback implementation;
  if (!gumjs_native_function_get (info, receiver, core, &func, &implementation))
    return;

  uint32_t argc = argv_array->Length ();

  Local<Value> * argv = nullptr;
  if (argc > 0)
  {
    auto context = isolate->GetCurrentContext ();

    argv = (Local<Value> *) g_alloca (argc * sizeof (Local<Value>));
    for (uint32_t i = 0; i != argc; i++)
    {
      new (&argv[i]) Local<Value> ();
      if (!argv_array->Get (context, i).ToLocal (&argv[i]))
      {
        for (uint32_t j = 0; j != i; j++)
          argv[j].~Local<Value> ();
        return;
      }
    }
  }

  gum_v8_native_function_invoke (func, implementation, info, argc, argv);

  for (uint32_t i = 0; i != argc; i++)
    argv[i].~Local<Value> ();
}

static gboolean
gumjs_native_function_get (const FunctionCallbackInfo<Value> & info,
                           Handle<Object> receiver,
                           GumV8Core * core,
                           GumV8NativeFunction ** func,
                           GCallback * implementation)
{
  auto isolate = core->isolate;

  auto native_function = Local<FunctionTemplate>::New (isolate,
      *core->native_function);
  auto holder = info.Holder ();
  if (native_function->HasInstance (holder))
  {
    auto f =
        (GumV8NativeFunction *) holder->GetAlignedPointerFromInternalField (1);

    *func = f;

    if (!receiver.IsEmpty ())
    {
      if (!_gum_v8_native_pointer_get (receiver, (gpointer *) implementation,
          core))
        return FALSE;
    }
    else
    {
      *implementation = f->implementation;
    }
  }
  else
  {
    if (receiver.IsEmpty () || !native_function->HasInstance (receiver))
    {
      _gum_v8_throw_ascii_literal (isolate, "expected a NativeFunction");
      return FALSE;
    }

    auto f = (GumV8NativeFunction *)
        receiver->GetAlignedPointerFromInternalField (1);
    *func = f;
    *implementation = f->implementation;
  }

  return TRUE;
}

static GumV8NativeFunction *
gumjs_native_function_init (Handle<Object> wrapper,
                            const GumV8NativeFunctionParams * params,
                            GumV8Core * core)
{
  auto isolate = core->isolate;
  GumV8NativeFunction * func;
  ffi_type * rtype;
  uint32_t nargs_fixed, nargs_total, i;
  gboolean is_variadic;
  ffi_abi abi;

  func = g_slice_new0 (GumV8NativeFunction);
  func->implementation = params->implementation;
  func->enable_detailed_return = params->enable_detailed_return;
  func->core = core;

  if (!gum_v8_ffi_type_get (core, params->return_type, &rtype, &func->data))
    goto error;

  nargs_fixed = nargs_total = params->argument_types->Length ();
  is_variadic = FALSE;
  func->atypes = g_new (ffi_type *, nargs_total);
  for (i = 0; i != nargs_total; i++)
  {
    auto type = params->argument_types->Get (i);
    String::Utf8Value type_utf8 (type);
    if (strcmp (*type_utf8, "...") == 0)
    {
      if (is_variadic)
      {
        _gum_v8_throw_ascii_literal (isolate,
            "only one variadic marker may be specified");
        goto error;
      }

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gum_v8_ffi_type_get (core, type,
        &func->atypes[is_variadic ? i - 1 : i], &func->data))
    {
      goto error;
    }
  }
  if (is_variadic)
    nargs_total--;

  abi = FFI_DEFAULT_ABI;
  if (!params->abi.IsEmpty ())
  {
    if (!gum_v8_ffi_abi_get (core, params->abi, &abi))
      goto error;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "failed to compile function call interface");
      goto error;
    }
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "failed to compile function call interface");
      goto error;
    }
  }

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  wrapper->SetInternalField (0, External::New (isolate,
      (void *) func->implementation));
  wrapper->SetAlignedPointerInInternalField (1, func);

  func->wrapper = new GumPersistent<Object>::type (isolate, wrapper);
  func->wrapper->SetWeak (func, gum_v8_native_function_on_weak_notify,
      WeakCallbackType::kParameter);
  func->wrapper->MarkIndependent ();

  g_hash_table_insert (core->native_functions, func, func);

  return func;

error:
  gum_v8_native_function_free (func);
  return NULL;
}

static void
gum_v8_native_function_free (GumV8NativeFunction * self)
{
  delete self->wrapper;

  while (self->data != NULL)
  {
    auto head = self->data;
    g_free (head->data);
    self->data = g_slist_delete_link (self->data, head);
  }
  g_free (self->atypes);

  g_slice_free (GumV8NativeFunction, self);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_v8_native_function_invoke (GumV8NativeFunction * self,
                               GCallback implementation,
                               const FunctionCallbackInfo<Value> & info,
                               uint32_t argc,
                               Handle<Value> * argv)
{
  auto core = (GumV8Core *) info.Data ().As<External> ()->Value ();
  auto isolate = core->isolate;
  gsize num_args_required = self->cif.nargs;
  gsize num_args_provided = (argv != nullptr) ? argc : info.Length ();
  GumExceptorScope scope;
  gint system_error = -1;

  if (num_args_provided != num_args_required)
  {
    _gum_v8_throw_ascii_literal (isolate, "bad argument count");
    return;
  }

  auto rtype = self->cif.rtype;

  gsize rsize = MAX (rtype->size, sizeof (gsize));
  gsize ralign = MAX (rtype->alignment, sizeof (gsize));
  auto rvalue = (GumFFIValue *) g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  void ** avalue;
  guint8 * avalues;

  if (num_args_required > 0)
  {
    avalue = (void **) g_alloca (num_args_required * sizeof (void *));

    gsize arglist_alignment = self->cif.arg_types[0]->alignment;
    avalues = (guint8 *) g_alloca (self->arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, self->arglist_size);

    gsize offset = 0;
    for (gsize i = 0; i != num_args_required; i++)
    {
      auto t = self->cif.arg_types[i];

      offset = GUM_ALIGN_SIZE (offset, t->alignment);

      auto v = (GumFFIValue *) (avalues + offset);

      if (!gum_v8_value_to_ffi_type (core,
          (argv != nullptr) ? argv[i] : info[i], v, t))
        return;
      avalue[i] = v;

      offset += t->size;
    }
  }
  else
  {
    avalue = NULL;
  }

  isolate->Exit ();

  {
    Unlocker ul (isolate);

    if (gum_exceptor_try (core->exceptor, &scope))
    {
      ffi_call (&self->cif, FFI_FN (implementation), rvalue, avalue);

      if (self->enable_detailed_return)
        system_error = gum_thread_get_system_error ();
    }
  }

  isolate->Enter ();

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
    return;
  }

  if (rtype != &ffi_type_void)
  {
    Local<Value> result;
    if (!gum_v8_value_from_ffi_type (core, &result, rvalue, rtype))
      return;

    if (self->enable_detailed_return)
    {
      auto context = isolate->GetCurrentContext ();

      auto template_return_value =
          Local<Object>::New (isolate, *core->native_return_value);
      auto return_value = template_return_value->Clone ();
      return_value->Set (context,
          Local<String>::New (isolate, *core->value_key),
          result).FromJust ();
      return_value->Set (context,
          Local<String>::New (isolate, *core->system_error_key),
          Integer::New (isolate, system_error)).FromJust ();
      info.GetReturnValue ().Set (return_value);
    }
    else
    {
      info.GetReturnValue ().Set (result);
    }
  }
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

static void
gum_v8_native_function_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeFunction> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->native_functions, self);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_system_function_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new SystemFunction()` to create a new instance");
    return;
  }

  GumV8NativeFunctionParams params;

  if (!_gum_v8_args_parse (args, "pVA|V", &params.implementation,
      &params.return_type, &params.argument_types, &params.abi))
    return;

  params.enable_detailed_return = TRUE;

  gumjs_native_function_init (wrapper, &params, core);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  Local<Function> func_value;
  Local<Value> rtype_value;
  Local<Array> atypes_array;
  Local<Value> abi_value;
  GumV8NativeCallback * callback;
  ffi_type * rtype;
  uint32_t nargs, i;
  ffi_abi abi;
  gpointer func = NULL;

  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new NativeCallback()` to create a new instance");
    return;
  }

  if (!_gum_v8_args_parse (args, "FVA|V", &func_value, &rtype_value,
      &atypes_array, &abi_value))
    return;

  callback = g_slice_new0 (GumV8NativeCallback);
  callback->func = new GumPersistent<Function>::type (isolate, func_value);
  callback->core = core;

  if (!gum_v8_ffi_type_get (core, rtype_value, &rtype, &callback->data))
    goto error;

  nargs = atypes_array->Length ();
  callback->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    if (!gum_v8_ffi_type_get (core, atypes_array->Get (i),
        &callback->atypes[i], &callback->data))
    {
      goto error;
    }
  }

  abi = FFI_DEFAULT_ABI;
  if (!abi_value.IsEmpty ())
  {
    if (!gum_v8_ffi_abi_get (core, abi_value, &abi))
      goto error;
  }

  callback->closure =
      (ffi_closure *) ffi_closure_alloc (sizeof (ffi_closure), &func);
  if (callback->closure == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to allocate closure");
    goto error;
  }

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
      callback->atypes) != FFI_OK)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "failed to compile function call interface");
    goto error;
  }

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
      gum_v8_native_callback_invoke, callback, func) != FFI_OK)
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to prepare closure");
    goto error;
  }

  wrapper->SetInternalField (0, External::New (isolate, func));

  callback->wrapper = new GumPersistent<Object>::type (isolate, wrapper);
  callback->wrapper->SetWeak (callback,
      gum_v8_native_callback_on_weak_notify, WeakCallbackType::kParameter);
  callback->wrapper->MarkIndependent ();

  g_hash_table_insert (core->native_callbacks, callback, callback);

  return;

error:
  gum_v8_native_callback_free (callback);
}

static void
gum_v8_native_callback_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeCallback> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->native_callbacks, self);
}

static void
gum_v8_native_callback_free (GumV8NativeCallback * self)
{
  delete self->wrapper;
  delete self->func;

  ffi_closure_free (self->closure);

  while (self->data != NULL)
  {
    auto head = self->data;
    g_free (head->data);
    self->data = g_slist_delete_link (self->data, head);
  }
  g_free (self->atypes);

  g_slice_free (GumV8NativeCallback, self);
}

static void
gum_v8_native_callback_invoke (ffi_cif * cif,
                               void * return_value,
                               void ** args,
                               void * user_data)
{
  auto self = (GumV8NativeCallback *) user_data;
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;

  auto rtype = cif->rtype;
  auto retval = (GumFFIValue *) return_value;
  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  auto argv = (Local<Value> *) g_alloca (cif->nargs * sizeof (Local<Value>));
  for (guint i = 0; i != cif->nargs; i++)
  {
    new (&argv[i]) Local<Value> ();
    if (!gum_v8_value_from_ffi_type (self->core, &argv[i],
        (GumFFIValue *) args[i], cif->arg_types[i]))
    {
      for (guint j = 0; j != i; j++)
        argv[j].~Local<Value> ();
      return;
    }
  }

  auto func (Local<Function>::New (isolate, *self->func));

  Local<Value> receiver;
  auto interceptor = &self->core->script->priv->interceptor;
  GumV8InvocationContext * jic = NULL;
  auto ic = gum_interceptor_get_current_invocation ();
  if (ic != NULL)
  {
    jic = _gum_v8_interceptor_obtain_invocation_context (interceptor);
    _gum_v8_invocation_context_reset (jic, ic);
    receiver = Local<Object>::New (isolate, *jic->object);
  }
  else
  {
    receiver = Undefined (isolate);
  }

  auto result = func->Call (receiver, cif->nargs, argv);

  if (jic != NULL)
  {
    _gum_v8_invocation_context_reset (jic, NULL);
    _gum_v8_interceptor_release_invocation_context (interceptor, jic);
  }

  if (cif->rtype != &ffi_type_void)
  {
    if (!scope.HasPendingException ())
      gum_v8_value_to_ffi_type (self->core, result, retval, cif->rtype);
  }

  for (guint i = 0; i != cif->nargs; i++)
    argv[i].~Local<Value> ();
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  GumCpuContext * cpu_context;
  gboolean is_mutable;
  if (!_gum_v8_args_parse (args, "Xt", &cpu_context, &is_mutable))
    return;

  wrapper->SetInternalField (0, External::New (isolate, cpu_context));
  wrapper->SetInternalField (1, Boolean::New (isolate, !!is_mutable));
  wrapper->SetAlignedPointerInInternalField (2, core);
}

static void
gumjs_cpu_context_get_register (Local<Name> property,
                                const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  auto cpu_context =
      (gpointer *) wrapper->GetInternalField (0).As<External> ()->Value ();
  gsize offset = info.Data ().As<Integer> ()->Value ();

  (void) property;

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (cpu_context[offset], core));
}

static void
gumjs_cpu_context_set_register (Local<Name> property,
                                Local<Value> value,
                                const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  auto cpu_context =
      (gpointer *) wrapper->GetInternalField (0).As<External> ()->Value ();
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  gsize offset = info.Data ().As<Integer> ()->Value ();

  (void) property;

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  gpointer ptr;
  if (!_gum_v8_native_pointer_parse (value, &ptr, core))
    return;

  cpu_context[offset] = ptr;
}

static MaybeLocal<Object>
gumjs_source_map_new (const gchar * json,
                      GumV8Core * core)
{
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto ctor = Local<FunctionTemplate>::New (isolate, *core->source_map);

  Local<Value> args[] = {
    String::NewFromUtf8 (isolate, json)
  };

  return ctor->GetFunction ()->NewInstance (context, G_N_ELEMENTS (args), args);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_source_map_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new SourceMap()` to create a new instance");
    return;
  }

  gchar * json;
  if (!_gum_v8_args_parse (args, "s", &json))
    return;

  auto handle = gum_source_map_new (json);

  g_free (json);

  if (handle == NULL)
  {
    _gum_v8_throw (isolate, "invalid source map");
    return;
  }

  auto map = gum_v8_source_map_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, map);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_source_map_resolve, GumV8SourceMap)
{
  guint line, column;

  if (args->info->Length () == 1)
  {
    if (!_gum_v8_args_parse (args, "u", &line))
      return;
    column = G_MAXUINT;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "uu", &line, &column))
      return;
  }

  const gchar * source, * name;
  if (gum_source_map_resolve (self->handle, &line, &column, &source, &name))
  {
    auto result = Array::New (isolate, 4);
    result->Set (0, String::NewFromUtf8 (isolate, source));
    result->Set (1, Integer::NewFromUnsigned (isolate, line));
    result->Set (2, Integer::NewFromUnsigned (isolate, column));
    if (name != NULL)
      result->Set (3, String::NewFromUtf8 (isolate, name));
    else
      result->Set (3, Null (isolate));
    info.GetReturnValue ().Set (result);
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static GumV8SourceMap *
gum_v8_source_map_new (Handle<Object> wrapper,
                       GumSourceMap * handle,
                       GumV8Core * core)
{
  auto map = g_slice_new (GumV8SourceMap);
  map->wrapper = new GumPersistent<Object>::type (core->isolate, wrapper);
  map->wrapper->MarkIndependent ();
  map->wrapper->SetWeak (map, gum_v8_source_map_on_weak_notify,
      WeakCallbackType::kParameter);
  map->handle = handle;

  map->core = core;

  g_hash_table_insert (core->source_maps, map, map);

  return map;
}

static void
gum_v8_source_map_free (GumV8SourceMap * self)
{
  g_object_unref (self->handle);

  delete self->wrapper;

  g_slice_free (GumV8SourceMap, self);
}

static void
gum_v8_source_map_on_weak_notify (const WeakCallbackInfo<GumV8SourceMap> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->source_maps, self);
}

static GumV8ExceptionSink *
gum_v8_exception_sink_new (Handle<Function> callback,
                           Isolate * isolate)
{
  auto sink = g_slice_new (GumV8ExceptionSink);
  sink->callback = new GumPersistent<Function>::type (isolate, callback);
  sink->isolate = isolate;
  return sink;
}

static void
gum_v8_exception_sink_free (GumV8ExceptionSink * sink)
{
  delete sink->callback;

  g_slice_free (GumV8ExceptionSink, sink);
}

static void
gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
                                        Handle<Value> exception)
{
  auto isolate = self->isolate;
  auto callback (Local<Function>::New (isolate, *self->callback));
  Handle<Value> argv[] = { exception };
  callback->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);
}

static GumV8MessageSink *
gum_v8_message_sink_new (Handle<Function> callback,
                         Isolate * isolate)
{
  auto sink = g_slice_new (GumV8MessageSink);
  sink->callback = new GumPersistent<Function>::type (isolate, callback);
  sink->isolate = isolate;
  return sink;
}

static void
gum_v8_message_sink_free (GumV8MessageSink * sink)
{
  delete sink->callback;

  g_slice_free (GumV8MessageSink, sink);
}

static void
gum_v8_message_sink_post (GumV8MessageSink * self,
                          const gchar * message,
                          GBytes * data)
{
  auto isolate = self->isolate;

  Local<Value> data_value;
  if (data != NULL)
  {
    gsize data_size;
    gpointer data_buffer = g_bytes_unref_to_data (data, &data_size);
    data_value = ArrayBuffer::New (isolate, data_buffer, data_size,
        ArrayBufferCreationMode::kInternalized);
  }
  else
  {
    data_value = Null (isolate);
  }

  auto callback (Local<Function>::New (isolate, *self->callback));
  Handle<Value> argv[] = {
    String::NewFromUtf8 (isolate, message),
    data_value
  };
  callback->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);
}

static const GumFFITypeMapping gum_ffi_type_mappings[] =
{
  { "void", &ffi_type_void },
  { "pointer", &ffi_type_pointer },
  { "int", &ffi_type_sint },
  { "uint", &ffi_type_uint },
  { "long", &ffi_type_slong },
  { "ulong", &ffi_type_ulong },
  { "char", &ffi_type_schar },
  { "uchar", &ffi_type_uchar },
  { "float", &ffi_type_float },
  { "double", &ffi_type_double },
  { "int8", &ffi_type_sint8 },
  { "uint8", &ffi_type_uint8 },
  { "int16", &ffi_type_sint16 },
  { "uint16", &ffi_type_uint16 },
  { "int32", &ffi_type_sint32 },
  { "uint32", &ffi_type_uint32 },
  { "int64", &ffi_type_sint64 },
  { "uint64", &ffi_type_uint64 },
  { "bool", &ffi_type_schar }
};

static const GumFFIABIMapping gum_ffi_abi_mappings[] =
{
  { "default", FFI_DEFAULT_ABI },
#if defined (X86_WIN64)
  { "win64", FFI_WIN64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 8
  { "unix64", FFI_UNIX64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 4
  { "sysv", FFI_SYSV },
  { "stdcall", FFI_STDCALL },
  { "thiscall", FFI_THISCALL },
  { "fastcall", FFI_FASTCALL },
# if defined (X86_WIN32)
  { "mscdecl", FFI_MS_CDECL },
# endif
#elif defined (ARM)
  { "sysv", FFI_SYSV },
# if GLIB_SIZEOF_VOID_P == 4
  { "vfp", FFI_VFP },
# endif
#endif
};

static gboolean
gum_v8_ffi_type_get (GumV8Core * core,
                     Handle<Value> name,
                     ffi_type ** type,
                     GSList ** data)
{
  auto isolate = core->isolate;

  if (name->IsString ())
  {
    String::Utf8Value str_value (name);
    auto str = *str_value;
    for (guint i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
    {
      auto m = &gum_ffi_type_mappings[i];
      if (strcmp (str, m->name) == 0)
      {
        *type = m->type;
        return TRUE;
      }
    }
  }
  else if (name->IsArray ())
  {
    auto fields_value = name.As<Array> ();
    gsize length = fields_value->Length ();

    auto fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    auto context = isolate->GetCurrentContext ();
    for (gsize i = 0; i != length; i++)
    {
      Local<Value> field_value;
      if (fields_value->Get (context, i).ToLocal (&field_value))
      {
        if (!gum_v8_ffi_type_get (core, field_value, &fields[i], data))
          return FALSE;
      }
      else
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid field type specified");
        return FALSE;
      }
    }

    fields[length] = NULL;

    auto struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid type specified");
  return FALSE;
}

static gboolean
gum_v8_ffi_abi_get (GumV8Core * core,
                    Handle<Value> name,
                    ffi_abi * abi)
{
  if (!name->IsString ())
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid abi specified");
    return FALSE;
  }

  String::Utf8Value str_value (name);
  auto str = *str_value;
  for (guint i = 0; i != G_N_ELEMENTS (gum_ffi_abi_mappings); i++)
  {
    auto m = &gum_ffi_abi_mappings[i];
    if (strcmp (str, m->name) == 0)
    {
      *abi = m->abi;
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (core->isolate, "invalid abi specified");
  return FALSE;
}

static gboolean
gum_v8_value_to_ffi_type (GumV8Core * core,
                          const Handle<Value> svalue,
                          GumFFIValue * value,
                          const ffi_type * type)
{
  auto isolate = core->isolate;

  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gum_v8_native_pointer_get (svalue, &value->v_pointer, core))
      return FALSE;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint8 = (gint8) svalue->Int32Value ();
  }
  else if (type == &ffi_type_uint8)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint8 = (guint8) svalue->Uint32Value ();
  }
  else if (type == &ffi_type_sint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint16 = (gint16) svalue->Int32Value ();
  }
  else if (type == &ffi_type_uint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint16 = (guint16) svalue->Uint32Value ();
  }
  else if (type == &ffi_type_sint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint32 = (gint32) svalue->Int32Value ();
  }
  else if (type == &ffi_type_uint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint32 = (guint32) svalue->Uint32Value ();
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gum_v8_int64_get (svalue, &value->v_sint64, core))
      return FALSE;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gum_v8_uint64_get (svalue, &value->v_uint64, core))
      return FALSE;
  }
  else if (type == &ffi_type_float)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_float = svalue->NumberValue ();
  }
  else if (type == &ffi_type_double)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_double = svalue->NumberValue ();
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    if (!svalue->IsArray ())
    {
      _gum_v8_throw_ascii_literal (isolate, "expected array with fields");
      return FALSE;
    }
    auto field_svalues = svalue.As<Array> ();

    auto field_types = type->elements;
    gsize provided_length = field_svalues->Length ();
    gsize length = 0;
    for (auto t = field_types; *t != NULL; t++)
      length++;
    if (provided_length != length)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "provided array length does not match number of fields");
      return FALSE;
    }

    auto field_values = (guint8 *) value;
    gsize offset = 0;
    auto context = isolate->GetCurrentContext ();
    for (gsize i = 0; i != length; i++)
    {
      auto field_type = field_types[i];

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      auto field_value = (GumFFIValue *) (field_values + offset);
      Local<Value> field_svalue;
      if (field_svalues->Get (context, i).ToLocal (&field_svalue))
      {
        if (!gum_v8_value_to_ffi_type (core, field_svalue, field_value,
            field_type))
        {
          return FALSE;
        }
      }
      else
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid field value specified");
        return FALSE;
      }

      offset += field_type->size;
    }
  }
  else
  {
    goto error_unsupported_type;
  }

  return TRUE;

error_expected_number:
  {
    _gum_v8_throw_ascii_literal (isolate, "expected number");
    return FALSE;
  }
error_unsupported_type:
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported type");
    return FALSE;
  }
}

static gboolean
gum_v8_value_from_ffi_type (GumV8Core * core,
                            Handle<Value> * svalue,
                            const GumFFIValue * value,
                            const ffi_type * type)
{
  auto isolate = core->isolate;

  if (type == &ffi_type_void)
  {
    *svalue = Undefined (isolate);
  }
  else if (type == &ffi_type_pointer)
  {
    *svalue = _gum_v8_native_pointer_new (value->v_pointer, core);
  }
  else if (type == &ffi_type_sint8)
  {
    *svalue = Integer::New (isolate, value->v_sint8);
  }
  else if (type == &ffi_type_uint8)
  {
    *svalue = Integer::NewFromUnsigned (isolate, value->v_uint8);
  }
  else if (type == &ffi_type_sint16)
  {
    *svalue = Integer::New (isolate, value->v_sint16);
  }
  else if (type == &ffi_type_uint16)
  {
    *svalue = Integer::NewFromUnsigned (isolate, value->v_uint16);
  }
  else if (type == &ffi_type_sint32)
  {
    *svalue = Integer::New (isolate, value->v_sint32);
  }
  else if (type == &ffi_type_uint32)
  {
    *svalue = Integer::NewFromUnsigned (isolate, value->v_uint32);
  }
  else if (type == &ffi_type_sint64)
  {
    *svalue = _gum_v8_int64_new (value->v_sint64, core);
  }
  else if (type == &ffi_type_uint64)
  {
    *svalue = _gum_v8_uint64_new (value->v_uint64, core);
  }
  else if (type == &ffi_type_float)
  {
    *svalue = Number::New (isolate, value->v_float);
  }
  else if (type == &ffi_type_double)
  {
    *svalue = Number::New (isolate, value->v_double);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    auto field_types = type->elements;

    gsize length = 0;
    for (auto t = field_types; *t != NULL; t++)
      length++;

    auto field_svalues = Array::New (isolate, length);
    auto field_values = (const guint8 *) value;
    gsize offset = 0;
    for (gsize i = 0; i != length; i++)
    {
      auto field_type = field_types[i];

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      auto field_value = (const GumFFIValue *) (field_values + offset);
      Local<Value> field_svalue;
      if (gum_v8_value_from_ffi_type (core, &field_svalue, field_value,
          field_type))
      {
        field_svalues->Set (i, field_svalue);
      }
      else
      {
        return FALSE;
      }

      offset += field_type->size;
    }
    *svalue = field_svalues;
  }
  else
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported type");
    return FALSE;
  }

  return TRUE;
}
