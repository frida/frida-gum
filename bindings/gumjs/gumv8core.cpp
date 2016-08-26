/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8core.h"

#include "gumv8scope.h"
#include "gumv8script-priv.h"

#include <ffi.h>
#include <string.h>

#if GLIB_SIZEOF_VOID_P == 4
# define GLIB_SIZEOF_VOID_P_IN_NIBBLE 8
#else
# define GLIB_SIZEOF_VOID_P_IN_NIBBLE 16
#endif

#define GUM_MAX_SEND_ARRAY_LENGTH (1024 * 1024)

using namespace v8;

typedef struct _GumFlushCallback GumFlushCallback;
typedef struct _GumWeakRef GumWeakRef;
typedef struct _GumFFIFunction GumFFIFunction;
typedef struct _GumFFICallback GumFFICallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;
typedef struct _GumCpuContextWrapper GumCpuContextWrapper;

struct _GumFlushCallback
{
  GumV8FlushNotify func;
  GumV8Script * script;
};

struct _GumWeakRef
{
  guint id;
  GumPersistent<Value>::type * target;
  GumPersistent<Function>::type * callback;
  GumV8Core * core;
};

struct _GumV8ScheduledCallback
{
  guint id;
  gboolean repeat;
  GumPersistent<Function>::type * func;
  GumPersistent<Value>::type * receiver;
  GSource * source;
  GumV8Core * core;
};

struct _GumV8ExceptionSink
{
  GumPersistent<Function>::type * callback;
  Isolate * isolate;
};

struct _GumV8MessageSink
{
  GumPersistent<Function>::type * callback;
  Isolate * isolate;
};

struct _GumFFIFunction
{
  GumV8Core * core;
  gpointer fn;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  GSList * data;
  GumPersistent<Object>::type * weak_instance;
};

struct _GumFFICallback
{
  GumV8Core * core;
  GumPersistent<Function>::type * func;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
  GSList * data;
  GumPersistent<Object>::type * weak_instance;
};

union _GumFFIValue
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

struct _GumFFITypeMapping
{
  const gchar * name;
  ffi_type * type;
};

struct _GumFFIABIMapping
{
  const gchar * name;
  ffi_abi abi;
};

struct _GumCpuContextWrapper
{
  GumPersistent<Object>::type * instance;
  GumCpuContext * cpu_context;
};

static gboolean gum_v8_core_notify_flushed_when_idle (gpointer user_data);

static void gum_v8_core_on_script_set_global_access_handler (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_global_get (Local<Name> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_core_on_global_query (Local<Name> property,
    const PropertyCallbackInfo<Integer> & info);
static void gum_v8_core_on_global_enumerate (
    const PropertyCallbackInfo<Array> & info);

static void gum_v8_core_on_script_pin (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_script_unpin (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_script_get_file_name (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_v8_core_on_script_get_source_map_data (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gum_v8_core_on_weak_ref_bind (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_weak_ref_unbind (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_clear_weak_ref_entry (guint id, GumWeakRef * ref);
static GumWeakRef * gum_weak_ref_new (guint id, Handle<Value> target,
    Handle<Function> callback, GumV8Core * core);
static void gum_weak_ref_clear (GumWeakRef * ref);
static void gum_weak_ref_free (GumWeakRef * ref);
static void gum_weak_ref_on_weak_notify (
    const WeakCallbackInfo<GumWeakRef> & info);
static void gum_v8_core_on_set_timeout (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_set_interval (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_clear_timeout (
    const FunctionCallbackInfo<Value> & info);
static GumV8ScheduledCallback * gum_v8_scheduled_callback_new (guint id,
    gboolean repeat, GSource * source, GumV8Core * core);
static void gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback);
static gboolean gum_v8_scheduled_callback_invoke (gpointer user_data);
static void gum_v8_core_on_send (const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_set_unhandled_exception_callback (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_set_incoming_message_callback (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_wait_for_event (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_core_on_new_int64 (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_add (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_sub (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_and (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_or (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_xor (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_shr (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_shl (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_compare (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_to_number (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_to_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_to_json (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_int64_value_of (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_core_on_new_uint64 (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_add (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_sub (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_and (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_or (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_xor (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_shr (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_shl (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_compare (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_to_number (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_to_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_to_json (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_uint64_value_of (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_core_on_new_native_pointer (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_is_null (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_add (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_sub (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_and (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_or (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_xor (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_shr (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_shl (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_compare (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_to_int32 (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_to_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_to_json (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_native_pointer_to_match_pattern (
    const FunctionCallbackInfo<Value> & info);

static void gum_v8_core_on_new_native_function (
    const FunctionCallbackInfo<Value> & info);
static void gum_ffi_function_on_weak_notify (
    const WeakCallbackInfo<GumFFIFunction> & info);
static void gum_v8_core_on_invoke_native_function (
    const FunctionCallbackInfo<Value> & info);
static void gum_ffi_function_free (GumFFIFunction * func);

static void gum_v8_core_on_new_native_callback (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_free_native_callback (
    const WeakCallbackInfo<GumFFICallback> & info);
static void gum_v8_core_on_invoke_native_callback (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);
static void gum_ffi_callback_free (GumFFICallback * callback);

static void gum_v8_core_on_new_cpu_context (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_core_on_cpu_context_get_register (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_v8_core_on_cpu_context_set_register (Local<String> property,
    Local<Value> value, const PropertyCallbackInfo<void> & info);

static GumV8ExceptionSink * gum_v8_exception_sink_new (
    Handle<Function> callback, Isolate * isolate);
static void gum_v8_exception_sink_free (GumV8ExceptionSink * sink);
static void gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
    Handle<Value> exception);

static GumV8MessageSink * gum_v8_message_sink_new (Handle<Function> callback,
    Isolate * isolate);
static void gum_v8_message_sink_free (GumV8MessageSink * sink);
static void gum_v8_message_sink_handle_message (GumV8MessageSink * self,
    const gchar * message);

static gboolean gum_v8_ffi_type_get (GumV8Core * core,
    Handle<Value> name, ffi_type ** type, GSList ** data);
static gboolean gum_v8_ffi_abi_get (GumV8Core * core,
    Handle<Value> name, ffi_abi * abi);
static gboolean gum_v8_value_to_ffi_type (GumV8Core * core,
    const Handle<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_v8_value_from_ffi_type (GumV8Core * core,
    Handle<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

static void gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info);

static gint64 gum_v8_int64_get_value (Handle<Object> object);
static void gum_v8_int64_set_value (Handle<Object> object, gint64 value,
    Isolate * isolate);

static guint64 gum_v8_uint64_get_value (Handle<Object> object);
static void gum_v8_uint64_set_value (Handle<Object> object, guint64 value,
    Isolate * isolate);

static const gchar * gum_exception_type_to_string (GumExceptionType type);

static void gum_cpu_context_on_weak_notify (
    const WeakCallbackInfo<GumCpuContextWrapper> & info);

void
_gum_v8_core_init (GumV8Core * self,
                   GumV8Script * script,
                   GumV8MessageEmitter message_emitter,
                   GumScriptScheduler * scheduler,
                   v8::Isolate * isolate,
                   Handle<ObjectTemplate> scope)
{
  self->script = script;
  self->backend = script->priv->backend;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->isolate = isolate;

  self->usage_count = 0;
  self->flush_notify = NULL;

  g_mutex_init (&self->event_mutex);
  g_cond_init (&self->event_cond);
  self->event_count = 0;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_weak_ref_free));

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> frida = ObjectTemplate::New ();
  frida->Set (String::NewFromUtf8 (isolate, "version"),
      String::NewFromUtf8 (isolate, FRIDA_VERSION), ReadOnly);
  scope->Set (String::NewFromUtf8 (isolate, "Frida"), frida);

  Handle<ObjectTemplate> script_module = ObjectTemplate::New ();
  script_module->Set (String::NewFromUtf8 (isolate, "pin"),
      FunctionTemplate::New (isolate, gum_v8_core_on_script_pin, data));
  script_module->Set (String::NewFromUtf8 (isolate, "unpin"),
      FunctionTemplate::New (isolate, gum_v8_core_on_script_unpin, data));
  script_module->Set (String::NewFromUtf8 (isolate, "runtime"),
      String::NewFromUtf8 (isolate, "V8"), ReadOnly);
  script_module->SetAccessor (String::NewFromUtf8 (isolate, "fileName"),
      gum_v8_core_on_script_get_file_name, NULL, data);
  script_module->SetAccessor (String::NewFromUtf8 (isolate, "_sourceMapData"),
      gum_v8_core_on_script_get_source_map_data, NULL, data);
  script_module->Set (String::NewFromUtf8 (isolate, "setGlobalAccessHandler"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_script_set_global_access_handler, data));
  NamedPropertyHandlerConfiguration global_access;
  global_access.getter = gum_v8_core_on_global_get;
  global_access.query = gum_v8_core_on_global_query;
  global_access.enumerator = gum_v8_core_on_global_enumerate;
  global_access.data = data;
  global_access.flags = PropertyHandlerFlags::kNonMasking;
  scope->SetHandler (global_access);
  scope->Set (String::NewFromUtf8 (isolate, "Script"), script_module);

  Handle<ObjectTemplate> weak = ObjectTemplate::New ();
  weak->Set (String::NewFromUtf8 (isolate, "bind"),
      FunctionTemplate::New (isolate, gum_v8_core_on_weak_ref_bind, data));
  weak->Set (String::NewFromUtf8 (isolate, "unbind"),
      FunctionTemplate::New (isolate, gum_v8_core_on_weak_ref_unbind,
          data));
  scope->Set (String::NewFromUtf8 (isolate, "WeakRef"), weak);

  scope->Set (String::NewFromUtf8 (isolate, "setTimeout"),
      FunctionTemplate::New (isolate, gum_v8_core_on_set_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "setInterval"),
      FunctionTemplate::New (isolate, gum_v8_core_on_set_interval, data));
  scope->Set (String::NewFromUtf8 (isolate, "clearTimeout"),
      FunctionTemplate::New (isolate, gum_v8_core_on_clear_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "clearInterval"),
      FunctionTemplate::New (isolate, gum_v8_core_on_clear_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "_send"),
      FunctionTemplate::New (isolate, gum_v8_core_on_send, data));
  scope->Set (String::NewFromUtf8 (isolate, "_setUnhandledExceptionCallback"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_set_unhandled_exception_callback, data));
  scope->Set (String::NewFromUtf8 (isolate, "_setIncomingMessageCallback"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_set_incoming_message_callback, data));
  scope->Set (String::NewFromUtf8 (isolate, "_waitForEvent"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_wait_for_event, data));

  Local<FunctionTemplate> int64 = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_int64, data);
  int64->SetClassName (String::NewFromUtf8 (isolate, "Int64"));
  Local<ObjectTemplate> int64_proto = int64->PrototypeTemplate ();
  int64_proto->Set (String::NewFromUtf8 (isolate, "add"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_add, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "sub"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_sub, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "and"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_and, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "or"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_or, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "xor"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_xor, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "shr"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_shr, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "shl"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_shl, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "compare"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_compare, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "toNumber"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_to_number, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_to_string, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "toJSON"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_to_json, data));
  int64_proto->Set (String::NewFromUtf8 (isolate, "valueOf"),
      FunctionTemplate::New (isolate, gum_v8_core_on_int64_value_of, data));
  int64->InstanceTemplate ()->SetInternalFieldCount (8 / GLIB_SIZEOF_VOID_P);
  scope->Set (String::NewFromUtf8 (isolate, "Int64"), int64);
  self->int64 = new GumPersistent<FunctionTemplate>::type (isolate, int64);

  Local<FunctionTemplate> uint64 = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_uint64, data);
  uint64->SetClassName (String::NewFromUtf8 (isolate, "UInt64"));
  Local<ObjectTemplate> uint64_proto = uint64->PrototypeTemplate ();
  uint64_proto->Set (String::NewFromUtf8 (isolate, "add"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_add, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "sub"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_sub, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "and"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_and, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "or"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_or, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "xor"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_xor, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "shr"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_shr, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "shl"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_shl, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "compare"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_compare, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "toNumber"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_to_number, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_to_string, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "toJSON"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_to_json, data));
  uint64_proto->Set (String::NewFromUtf8 (isolate, "valueOf"),
      FunctionTemplate::New (isolate, gum_v8_core_on_uint64_value_of, data));
  uint64->InstanceTemplate ()->SetInternalFieldCount (8 / GLIB_SIZEOF_VOID_P);
  scope->Set (String::NewFromUtf8 (isolate, "UInt64"), uint64);
  self->uint64 = new GumPersistent<FunctionTemplate>::type (isolate, uint64);

  Local<FunctionTemplate> native_pointer = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_native_pointer, data);
  native_pointer->SetClassName (
      String::NewFromUtf8 (isolate, "NativePointer"));
  Local<ObjectTemplate> native_pointer_proto =
      native_pointer->PrototypeTemplate ();
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "isNull"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_is_null));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "add"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_add, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "sub"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_sub, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "and"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_and, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "or"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_or, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "xor"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_xor, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "shr"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_shr, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "shl"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_shl, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "compare"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_compare, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toInt32"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_to_int32, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_to_string, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toJSON"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_to_json, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toMatchPattern"),
      FunctionTemplate::New (isolate,
          gum_v8_core_on_native_pointer_to_match_pattern, data));
  native_pointer->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "NativePointer"), native_pointer);
  self->native_pointer =
      new GumPersistent<FunctionTemplate>::type (isolate, native_pointer);

  Local<FunctionTemplate> native_function = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_native_function, data);
  native_function->SetClassName (
      String::NewFromUtf8 (isolate, "NativeFunction"));
  native_function->Inherit (native_pointer);
  Local<ObjectTemplate> native_function_object =
      native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gum_v8_core_on_invoke_native_function, data);
  native_function_object->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, "NativeFunction"),
      native_function);

  Local<FunctionTemplate> native_callback = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_native_callback, data);
  native_callback->SetClassName (
      String::NewFromUtf8 (isolate, "NativeCallback"));
  native_callback->Inherit (native_pointer);
  native_callback->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "NativeCallback"),
      native_callback);

  Local<FunctionTemplate> cpu_context = FunctionTemplate::New (isolate,
      gum_v8_core_on_new_cpu_context, data);
  cpu_context->SetClassName (
      String::NewFromUtf8 (isolate, "CpuContext"));
  Local<ObjectTemplate> cpu_context_object =
      cpu_context->InstanceTemplate ();
  cpu_context_object->SetInternalFieldCount (3);
  Local<AccessorSignature> cpu_context_signature =
      AccessorSignature::New (isolate, cpu_context);

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  cpu_context_object->SetAccessor (String::NewFromOneByte (isolate, \
      reinterpret_cast<const uint8_t *> (G_STRINGIFY (A))), \
      gum_v8_core_on_cpu_context_get_register, \
      gum_v8_core_on_cpu_context_set_register, \
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

  scope->Set (String::NewFromUtf8 (isolate, "CpuContext"), cpu_context);
  self->cpu_context =
      new GumPersistent<FunctionTemplate>::type (isolate, cpu_context);
}

void
_gum_v8_core_realize (GumV8Core * self)
{
  Isolate * isolate = self->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  Local<Object> global = context->Global ();
  global->Set (String::NewFromUtf8 (isolate, "global"), global);

  self->native_functions = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_ffi_function_free));

  self->native_callbacks = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_ffi_callback_free));

  self->native_resources = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (_gum_v8_native_resource_free));

  Local<Value> zero (Number::New (isolate, 0));

  Local<FunctionTemplate> int64 (
      Local<FunctionTemplate>::New (isolate, *self->int64));
  MaybeLocal<Object> maybe_int64_value =
      int64->GetFunction ()->NewInstance (context, 1, &zero);
  Local<Object> int64_value;
  bool success = maybe_int64_value.ToLocal (&int64_value);
  g_assert (success);
  self->int64_value = new GumPersistent<Object>::type (isolate,
      int64_value);

  Local<FunctionTemplate> uint64 (
      Local<FunctionTemplate>::New (isolate, *self->uint64));
  MaybeLocal<Object> maybe_uint64_value =
      uint64->GetFunction ()->NewInstance (context, 1, &zero);
  Local<Object> uint64_value;
  success = maybe_uint64_value.ToLocal (&uint64_value);
  g_assert (success);
  self->uint64_value = new GumPersistent<Object>::type (isolate,
      uint64_value);

  Local<FunctionTemplate> native_pointer (
      Local<FunctionTemplate>::New (isolate, *self->native_pointer));
  MaybeLocal<Object> maybe_native_pointer_value =
      native_pointer->GetFunction ()->NewInstance (context, 1, &zero);
  Local<Object> native_pointer_value;
  success = maybe_native_pointer_value.ToLocal (&native_pointer_value);
  g_assert (success);
  self->native_pointer_value = new GumPersistent<Object>::type (isolate,
      native_pointer_value);
  self->handle_key = new GumPersistent<String>::type (isolate,
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> ("handle"),
          NewStringType::kNormal,
          -1).ToLocalChecked ());

  Local<FunctionTemplate> cpu_context (
      Local<FunctionTemplate>::New (isolate, *self->cpu_context));
  Local<Value> args[2] = {
      External::New (isolate, NULL),
      Boolean::New (isolate, false)
  };
  MaybeLocal<Object> maybe_cpu_context_value =
      cpu_context->GetFunction ()->NewInstance (
          context, G_N_ELEMENTS (args), args);
  Local<Object> cpu_context_value;
  success = maybe_cpu_context_value.ToLocal (&cpu_context_value);
  g_assert (success);
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
    GumV8ScheduledCallback * callback = static_cast<GumV8ScheduledCallback *> (
        self->scheduled_callbacks->data);
    GSource * source;

    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);

    source = g_source_ref (callback->source);

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

  g_hash_table_foreach (self->weak_refs,
      (GHFunc) gum_v8_core_clear_weak_ref_entry, NULL);
  g_hash_table_remove_all (self->weak_refs);

  done = self->usage_count == 1;
  if (done)
    self->flush_notify = NULL;

  return done;
}

void
_gum_v8_core_notify_flushed (GumV8Core * self,
                             GumV8FlushNotify func)
{
  GumFlushCallback * callback;
  GSource * source;

  callback = g_slice_new (GumFlushCallback);
  callback->func = func;
  callback->script = self->script;

  source = g_idle_source_new ();
  g_source_set_callback (source, gum_v8_core_notify_flushed_when_idle, callback,
      NULL);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  g_source_unref (source);
}

static gboolean
gum_v8_core_notify_flushed_when_idle (gpointer user_data)
{
  GumFlushCallback * callback = (GumFlushCallback *) user_data;

  callback->func (callback->script);

  g_slice_free (GumFlushCallback, callback);

  return FALSE;
}

void
_gum_v8_core_dispose (GumV8Core * self)
{
  g_hash_table_unref (self->native_resources);
  self->native_resources = NULL;

  g_hash_table_unref (self->native_callbacks);
  self->native_callbacks = NULL;

  g_hash_table_unref (self->native_functions);
  self->native_functions = NULL;

  gum_v8_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  gum_v8_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

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

  delete self->cpu_context_value;
  self->cpu_context_value = nullptr;
}

void
_gum_v8_core_finalize (GumV8Core * self)
{
  g_hash_table_unref (self->weak_refs);
  self->weak_refs = NULL;

  delete self->native_pointer;
  self->native_pointer = NULL;

  delete self->int64;
  self->int64 = NULL;

  delete self->uint64;
  self->uint64 = NULL;

  delete self->cpu_context;
  self->cpu_context = NULL;

  g_object_unref (self->exceptor);
  self->exceptor = NULL;

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
  if (self->unhandled_exception_sink != NULL)
  {
    gum_v8_exception_sink_handle_exception (self->unhandled_exception_sink,
        exception);
  }
}

void
_gum_v8_core_post_message (GumV8Core * self,
                           const gchar * message)
{
  bool delivered = false;

  {
    Locker locker (self->isolate);

    if (self->incoming_message_sink != NULL)
    {
      ScriptScope scope (self->script);
      gum_v8_message_sink_handle_message (self->incoming_message_sink, message);
      delivered = true;
    }
  }

  if (delivered)
  {
    g_mutex_lock (&self->event_mutex);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    g_mutex_unlock (&self->event_mutex);
  }
}

static void
gum_v8_core_on_script_pin (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  _gum_v8_core_pin (self);
}

static void
gum_v8_core_on_script_unpin (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  _gum_v8_core_unpin (self);
}

static void
gum_v8_core_on_script_get_file_name (Local<String> property,
                                     const PropertyCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  GumV8ScriptPrivate * priv = self->script->priv;

  Local<Value> result;
  if (priv->code != nullptr)
  {
    Isolate * isolate = info.GetIsolate ();
    Local<Script> code (Local<Script>::New (isolate, *priv->code));
    Local<Value> file_name (code->GetUnboundScript ()->GetScriptName ());

    if (file_name->IsString ())
      result = file_name;
  }

  if (!result.IsEmpty ())
    info.GetReturnValue ().Set (result);
  else
    info.GetReturnValue ().SetNull ();
}

static void
gum_v8_core_on_script_get_source_map_data (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  GumV8ScriptPrivate * priv = self->script->priv;

  Local<Value> result;
  if (priv->code != nullptr)
  {
    Isolate * isolate = info.GetIsolate ();
    Local<Script> code (Local<Script>::New (isolate, *priv->code));
    Local<Value> url_value (code->GetUnboundScript ()->GetSourceMappingURL ());

    if (url_value->IsString ())
    {
      String::Utf8Value url_utf8 (url_value);
      const gchar * url = *url_utf8;
      if (g_str_has_prefix (url, "data:application/json;base64,"))
      {
        gsize size;
        gchar * data;

        data = (gchar *) g_base64_decode (url + 29, &size);
        if (data != NULL && g_utf8_validate (data, size, NULL))
        {
          result = String::NewFromUtf8 (isolate, data, String::kNormalString,
              size);
        }
        g_free (data);
      }
    }
  }

  if (!result.IsEmpty ())
    info.GetReturnValue ().Set (result);
  else
    info.GetReturnValue ().SetNull ();
}

static void
gum_v8_core_on_script_set_global_access_handler (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () == 0 || !info[0]->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected an object with callbacks, or null")));
    return;
  }

  Local<Object> callbacks (info[0].As<Object> ());
  Local<Function> on_enumerate, on_get;
  bool has_callbacks = !callbacks->IsNull ();
  if (has_callbacks)
  {
    if (!_gum_v8_callbacks_get (callbacks, "enumerate", &on_enumerate, self))
      return;
    if (!_gum_v8_callbacks_get (callbacks, "get", &on_get, self))
      return;
  }

  delete self->on_global_enumerate;
  delete self->on_global_get;
  delete self->global_receiver;
  self->on_global_enumerate = nullptr;
  self->on_global_get = nullptr;
  self->global_receiver = nullptr;

  if (has_callbacks)
  {
    self->on_global_enumerate = new GumPersistent<Function>::type (isolate,
        on_enumerate.As<Function> ());
    self->on_global_get = new GumPersistent<Function>::type (isolate,
        on_get.As<Function> ());
    self->global_receiver = new GumPersistent<Object>::type (isolate,
        callbacks);
  }
}

static void
gum_v8_core_on_global_get (Local<Name> property,
                           const PropertyCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  if (self->on_global_get == nullptr)
    return;

  Isolate * isolate = info.GetIsolate ();

  Local<Function> get (Local<Function>::New (isolate, *self->on_global_get));
  Local<Object> receiver (Local<Object>::New (isolate, *self->global_receiver));
  Handle<Value> argv[] = { property };
  Local<Value> result = get->Call (receiver, 1, argv);
  if (!result.IsEmpty () && !result->IsUndefined ())
  {
    info.GetReturnValue ().Set (result);
  }
}

static void
gum_v8_core_on_global_query (Local<Name> property,
                             const PropertyCallbackInfo<Integer> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  if (self->on_global_get == nullptr)
    return;

  Isolate * isolate = info.GetIsolate ();

  Local<Function> get (Local<Function>::New (isolate, *self->on_global_get));
  Local<Object> receiver (Local<Object>::New (isolate, *self->global_receiver));
  Handle<Value> argv[] = { property };
  Local<Value> result = get->Call (receiver, 1, argv);
  if (!result.IsEmpty () && !result->IsUndefined ())
  {
    info.GetReturnValue ().Set (PropertyAttribute::ReadOnly |
        PropertyAttribute::DontDelete);
  }
}

static void
gum_v8_core_on_global_enumerate (const PropertyCallbackInfo<Array> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  if (self->on_global_enumerate == nullptr)
    return;

  Isolate * isolate = info.GetIsolate ();

  Local<Function> enumerate (
      Local<Function>::New (isolate, *self->on_global_enumerate));
  Local<Object> receiver (Local<Object>::New (isolate, *self->global_receiver));
  Local<Value> result = enumerate->Call (receiver, 0, nullptr);
  if (!result.IsEmpty () && result->IsArray ())
  {
    info.GetReturnValue ().Set (result.As<Array> ());
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
static void
gum_v8_core_on_weak_ref_bind (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();
  GumWeakRef * ref;

  Local<Value> target = info[0];
  if (target->IsUndefined () || target->IsNull ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "first argument must be a value with a regular lifespan")));
    return;
  }

  Local<Value> callback_val = info[1];
  if (!callback_val->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "second argument must be a function")));
    return;
  }

  guint id = ++self->last_weak_ref_id;

  ref = gum_weak_ref_new (id, target, callback_val.As <Function> (), self);
  g_hash_table_insert (self->weak_refs, GUINT_TO_POINTER (id), ref);

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
static void
gum_v8_core_on_weak_ref_unbind (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> id_val = info[0];
  if (!id_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "argument must be a weak ref id")));
    return;
  }
  guint id = id_val->ToUint32 ()->Value ();

  bool removed =
      !!g_hash_table_remove (self->weak_refs, GUINT_TO_POINTER (id));

  info.GetReturnValue ().Set (removed);
}

static void
gum_v8_core_clear_weak_ref_entry (guint id,
                                  GumWeakRef * ref)
{
  (void) id;

  gum_weak_ref_clear (ref);
}

static GumWeakRef *
gum_weak_ref_new (guint id,
                  Handle<Value> target,
                  Handle<Function> callback,
                  GumV8Core * core)
{
  GumWeakRef * ref;
  Isolate * isolate = core->isolate;

  ref = g_slice_new (GumWeakRef);
  ref->id = id;
  ref->target = new GumPersistent<Value>::type (isolate, target);
  ref->target->SetWeak (ref, gum_weak_ref_on_weak_notify,
      WeakCallbackType::kParameter);
  ref->target->MarkIndependent ();
  ref->callback = new GumPersistent<Function>::type (isolate, callback);
  ref->core = core;

  return ref;
}

static void
gum_weak_ref_clear (GumWeakRef * ref)
{
  if (ref->target != nullptr)
  {
    delete ref->target;
    ref->target = nullptr;
  }
}

static void
gum_weak_ref_free (GumWeakRef * ref)
{
  gum_weak_ref_clear (ref);

  {
    ScriptScope scope (ref->core->script);
    Isolate * isolate = ref->core->isolate;
    Local<Function> callback (Local<Function>::New (isolate, *ref->callback));
    callback->Call (Null (isolate), 0, NULL);
  }
  delete ref->callback;

  g_slice_free (GumWeakRef, ref);
}

static void
gum_weak_ref_on_weak_notify (const WeakCallbackInfo<GumWeakRef> & info)
{
  GumWeakRef * self = info.GetParameter ();

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
  GSList * link;

  link = g_slist_find (self->scheduled_callbacks, callback);
  if (link == NULL)
    return FALSE;

  self->scheduled_callbacks =
      g_slist_delete_link (self->scheduled_callbacks, link);
  return TRUE;
}

static void
gum_v8_core_on_schedule_callback (const FunctionCallbackInfo<Value> & info,
                                  gboolean repeat)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  Local<Value> func_val = info[0];
  if (!func_val->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "first argument must be a function")));
    return;
  }

  gsize delay = 0;
  if (info.Length () > 1 && !_gum_v8_size_get (info[1], &delay, self))
    return;

  guint id = ++self->last_callback_id;
  GSource * source;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);
  GumV8ScheduledCallback * callback =
      gum_v8_scheduled_callback_new (id, repeat, source, self);
  callback->func = new GumPersistent<Function>::type (isolate,
      func_val.As <Function> ());
  callback->receiver = new GumPersistent<Value>::type (isolate, info.This ());
  g_source_set_callback (source, gum_v8_scheduled_callback_invoke, callback,
      reinterpret_cast<GDestroyNotify> (gum_v8_scheduled_callback_free));
  gum_v8_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));

  info.GetReturnValue ().Set (id);
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
static void
gum_v8_core_on_set_timeout (const FunctionCallbackInfo<Value> & info)
{
  gum_v8_core_on_schedule_callback (info, FALSE);
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
static void
gum_v8_core_on_set_interval (const FunctionCallbackInfo<Value> & info)
{
  gum_v8_core_on_schedule_callback (info, TRUE);
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
static void
gum_v8_core_on_clear_timeout (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;
  GSList * cur;

  Local<Value> id_val = info[0];
  if (!id_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "argument must be a timeout id")));
    return;
  }
  guint id = id_val->ToUint32 ()->Value ();

  GumV8ScheduledCallback * callback = NULL;
  for (cur = self->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumV8ScheduledCallback * cb =
        static_cast<GumV8ScheduledCallback *> (cur->data);
    if (cb->id == id)
    {
      callback = cb;
      self->scheduled_callbacks =
          g_slist_delete_link (self->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
  {
    GSource * source;

    source = g_source_ref (callback->source);

    _gum_v8_core_pin (self);

    self->isolate->Exit ();
    {
      Unlocker ul (self->isolate);

      g_source_destroy (source);
      g_source_unref (source);
    }
    self->isolate->Enter ();
  }

  info.GetReturnValue ().Set (callback != NULL);
}

static GumV8ScheduledCallback *
gum_v8_scheduled_callback_new (guint id,
                               gboolean repeat,
                               GSource * source,
                               GumV8Core * core)
{
  GumV8ScheduledCallback * callback;

  callback = g_slice_new (GumV8ScheduledCallback);
  callback->id = id;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback)
{
  GumV8Core * core = callback->core;

  {
    ScriptScope scope (core->script);

    delete callback->func;
    delete callback->receiver;

    _gum_v8_core_unpin (core);
  }

  g_source_unref (callback->source);

  g_slice_free (GumV8ScheduledCallback, callback);
}

static gboolean
gum_v8_scheduled_callback_invoke (gpointer user_data)
{
  GumV8ScheduledCallback * self =
      static_cast<GumV8ScheduledCallback *> (user_data);
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;

  ScriptScope scope (core->script);
  Local<Function> func (Local<Function>::New (isolate, *self->func));
  Local<Value> receiver (Local<Value>::New (isolate, *self->receiver));
  func->Call (receiver, 0, NULL);

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
static void
gum_v8_core_on_send (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  GumInterceptor * interceptor = self->script->priv->interceptor.interceptor;

  String::Utf8Value message (info[0]);

  Local<Value> data_value = info[1];
  GBytes * data = NULL;
  if (!data_value->IsUndefined () && !data_value->IsNull ())
  {
    data = _gum_v8_byte_array_get (data_value, self);
    if (data == NULL)
      return;
  }

  /*
   * Synchronize Interceptor state before sending the message. The application
   * might be waiting for an acknowledgement that APIs have been instrumented.
   *
   * This is very important for the RPC API.
   */
  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  self->message_emitter (self->script, *message, data);

  g_bytes_unref (data);
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
static void
gum_v8_core_on_set_unhandled_exception_callback (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  bool argument_valid = false;
  Local<Function> callback;
  if (info.Length () >= 1)
  {
    Local<Value> argument = info[0];
    if (argument->IsFunction ())
    {
      argument_valid = true;
      callback = argument.As<Function> ();
    }
    else if (argument->IsNull ())
    {
      argument_valid = true;
    }
  }
  if (!argument_valid)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid argument")));
    return;
  }

  gum_v8_exception_sink_free (self->unhandled_exception_sink);
  self->unhandled_exception_sink = NULL;

  if (!callback.IsEmpty ())
    self->unhandled_exception_sink = gum_v8_exception_sink_new (callback, isolate);
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
static void
gum_v8_core_on_set_incoming_message_callback (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  bool argument_valid = false;
  Local<Function> callback;
  if (info.Length () >= 1)
  {
    Local<Value> argument = info[0];
    if (argument->IsFunction ())
    {
      argument_valid = true;
      callback = argument.As<Function> ();
    }
    else if (argument->IsNull ())
    {
      argument_valid = true;
    }
  }
  if (!argument_valid)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid argument")));
    return;
  }

  gum_v8_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (!callback.IsEmpty ())
    self->incoming_message_sink = gum_v8_message_sink_new (callback, isolate);
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
static void
gum_v8_core_on_wait_for_event (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  self->isolate->Exit ();
  {
    Unlocker ul (self->isolate);

    g_mutex_lock (&self->event_mutex);
    guint start_count = self->event_count;
    while (self->event_count == start_count)
      g_cond_wait (&self->event_cond, &self->event_mutex);
    g_mutex_unlock (&self->event_mutex);
  }
  self->isolate->Enter ();
}

static void
gum_v8_core_on_new_int64 (const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();
  gint64 value;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new Int64()` to create a new instance,"
        " or use the shorthand: `int64()`")));
    return;
  }

  if (info.Length () == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Int64: expected a string or number")));
    return;
  }

  Local<Value> argument = info[0];
  if (argument->IsString ())
  {
    String::Utf8Value value_as_utf8 (argument);
    const gchar * value_as_string = *value_as_utf8;
    gchar * endvalue;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      value = g_ascii_strtoll (value_as_string + 2, &endvalue, 16);
      if (endvalue == value_as_string + 2)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "Int64: argument is not a valid hexadecimal string")));
        return;
      }
    }
    else
    {
      value = g_ascii_strtoll (value_as_string, &endvalue, 10);
      if (endvalue == value_as_string)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "Int64: argument is not a valid decimal string")));
        return;
      }
    }
  }
  else if (argument->IsNumber ())
  {
    value = argument.As<Number> ()->Value ();
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Int64: expected a string or number")));
    return;
  }

  gum_v8_int64_set_value (info.Holder (), value, isolate);
}

#define GUM_DEFINE_INT64_OP_IMPL(name, op) \
    static void \
    gum_v8_core_on_int64_ ## name ( \
        const FunctionCallbackInfo<Value> & info) \
    { \
        GumV8Core * self = static_cast<GumV8Core *> ( \
            info.Data ().As<External> ()->Value ()); \
        \
        gint64 lhs = gum_v8_int64_get_value (info.Holder ()); \
        \
        gint64 rhs; \
        Local<FunctionTemplate> int64 ( \
            Local<FunctionTemplate>::New (self->isolate, \
                *self->int64)); \
        if (int64->HasInstance (info[0])) \
        { \
          rhs = gum_v8_int64_get_value (info[0].As<Object> ()); \
        } \
        else \
        { \
          rhs = info[0]->ToInteger ()->Value (); \
        } \
        gint64 result = lhs op rhs; \
        \
        info.GetReturnValue ().Set (_gum_v8_int64_new (result, self)); \
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
static void
gum_v8_core_on_int64_compare (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  gint64 lhs = gum_v8_int64_get_value (info.Holder ());

  gint64 rhs;
  Local<FunctionTemplate> int64 (
      Local<FunctionTemplate>::New (self->isolate, *self->int64));
  if (int64->HasInstance (info[0]))
  {
    rhs = gum_v8_int64_get_value (info[0].As<Object> ());
  }
  else
  {
    rhs = info[0]->ToInteger ()->Value ();
  }
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
static void
gum_v8_core_on_int64_to_number (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<double> (
      gum_v8_int64_get_value (info.Holder ())));
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
static void
gum_v8_core_on_int64_to_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gint64 value = gum_v8_int64_get_value (info.Holder ());
  gint radix = (info.Length () > 0) ? info[0]->Int32Value () : 10;
  if (radix != 10 && radix != 16)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "unsupported radix")));
    return;
  }

  gchar buf[32];
  if (radix == 10)
    sprintf (buf, "%" G_GINT64_FORMAT, value);
  else if (value >= 0)
    sprintf (buf, "%" G_GINT64_MODIFIER "x", value);
  else
    sprintf (buf, "-%" G_GINT64_MODIFIER "x", -value);

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_int64_to_json (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gchar buf[32];
  sprintf (buf, "%" G_GINT64_FORMAT, gum_v8_int64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_int64_value_of (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<double> (
      gum_v8_int64_get_value (info.Holder ())));
}

static void
gum_v8_core_on_new_uint64 (const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();
  guint64 value;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new UInt64()` to create a new instance,"
        " or use the shorthand: `uint64()`")));
    return;
  }

  if (info.Length () == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "UInt64: expected a string or number")));
    return;
  }

  Local<Value> argument = info[0];
  if (argument->IsString ())
  {
    String::Utf8Value value_as_utf8 (argument);
    const gchar * value_as_string = *value_as_utf8;
    gchar * endvalue;
    if (g_str_has_prefix (value_as_string, "0x"))
    {
      value = g_ascii_strtoull (value_as_string + 2, &endvalue, 16);
      if (endvalue == value_as_string + 2)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "UInt64: argument is not a valid hexadecimal string")));
        return;
      }
    }
    else
    {
      value = g_ascii_strtoull (value_as_string, &endvalue, 10);
      if (endvalue == value_as_string)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "UInt64: argument is not a valid decimal string")));
        return;
      }
    }
  }
  else if (argument->IsNumber ())
  {
    value = argument.As<Number> ()->Value ();
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "UInt64: expected a string or number")));
    return;
  }

  gum_v8_uint64_set_value (info.Holder (), value, isolate);
}

#define GUM_DEFINE_UINT64_OP_IMPL(name, op) \
    static void \
    gum_v8_core_on_uint64_ ## name ( \
        const FunctionCallbackInfo<Value> & info) \
    { \
        GumV8Core * self = static_cast<GumV8Core *> ( \
            info.Data ().As<External> ()->Value ()); \
        \
        guint64 lhs = gum_v8_uint64_get_value (info.Holder ()); \
        \
        guint64 rhs; \
        Local<FunctionTemplate> uint64 ( \
            Local<FunctionTemplate>::New (self->isolate, \
                *self->uint64)); \
        if (uint64->HasInstance (info[0])) \
        { \
          rhs = gum_v8_uint64_get_value (info[0].As<Object> ()); \
        } \
        else \
        { \
          rhs = info[0]->ToInteger ()->Value (); \
        } \
        guint64 result = lhs op rhs; \
        \
        info.GetReturnValue ().Set (_gum_v8_uint64_new (result, self)); \
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
static void
gum_v8_core_on_uint64_compare (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  guint64 lhs = gum_v8_uint64_get_value (info.Holder ());

  guint64 rhs;
  Local<FunctionTemplate> uint64 (
      Local<FunctionTemplate>::New (self->isolate, *self->uint64));
  if (uint64->HasInstance (info[0]))
  {
    rhs = gum_v8_uint64_get_value (info[0].As<Object> ());
  }
  else
  {
    rhs = info[0]->ToInteger ()->Value ();
  }
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
static void
gum_v8_core_on_uint64_to_number (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<double> (
      gum_v8_uint64_get_value (info.Holder ())));
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
static void
gum_v8_core_on_uint64_to_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  guint64 value = gum_v8_uint64_get_value (info.Holder ());
  gint radix = (info.Length () > 0) ? info[0]->Int32Value () : 10;
  if (radix != 10 && radix != 16)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "unsupported radix")));
    return;
  }

  gchar buf[32];
  if (radix == 10)
    sprintf (buf, "%" G_GUINT64_FORMAT, value);
  else
    sprintf (buf, "%" G_GINT64_MODIFIER "x", value);

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_uint64_to_json (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gchar buf[32];
  sprintf (buf, "%" G_GUINT64_FORMAT, gum_v8_uint64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_uint64_value_of (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<double> (
      gum_v8_uint64_get_value (info.Holder ())));
}

static void
gum_v8_core_on_new_native_pointer (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * core = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new NativePointer()` to create a new instance,"
        " or use one of the two shorthands: `ptr()` and `NULL`")));
    return;
  }

  if (info.Length () == 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "NativePointer: expected an argument")));
    return;
  }

  gpointer value;
  if (!_gum_v8_native_pointer_parse (info[0], &value, core))
    return;

  info.Holder ()->SetInternalField (0,
      External::New (info.GetIsolate (), value));
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
static void
gum_v8_core_on_native_pointer_is_null (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()) == 0);
}

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
    static void \
    gum_v8_core_on_native_pointer_ ## name ( \
        const FunctionCallbackInfo<Value> & info) \
    { \
        GumV8Core * self = static_cast<GumV8Core *> ( \
            info.Data ().As<External> ()->Value ()); \
        \
        guint64 lhs = reinterpret_cast<guint64> ( \
            GUMJS_NATIVE_POINTER_VALUE (info.Holder ())); \
        \
        guint64 rhs; \
        Local<FunctionTemplate> native_pointer ( \
            Local<FunctionTemplate>::New (self->isolate, \
                *self->native_pointer)); \
        if (native_pointer->HasInstance (info[0])) \
        { \
          rhs = reinterpret_cast<guint64> ( \
              GUMJS_NATIVE_POINTER_VALUE (info[0].As<Object> ())); \
        } \
        else \
        { \
          rhs = info[0]->ToInteger ()->Value (); \
        } \
        gpointer result = GSIZE_TO_POINTER (lhs op rhs); \
        \
        info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, self)); \
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
static void
gum_v8_core_on_native_pointer_compare (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());

  guint64 lhs = reinterpret_cast<guint64> (
      GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  guint64 rhs;
  Local<FunctionTemplate> native_pointer (
      Local<FunctionTemplate>::New (self->isolate,
          *self->native_pointer));
  if (native_pointer->HasInstance (info[0]))
  {
    rhs = reinterpret_cast<guint64> (
        GUMJS_NATIVE_POINTER_VALUE (info[0].As<Object> ()));
  }
  else
  {
    rhs = info[0]->ToInteger ()->Value ();
  }
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
static void
gum_v8_core_on_native_pointer_to_int32 (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<int32_t> (GPOINTER_TO_SIZE (
      GUMJS_NATIVE_POINTER_VALUE (info.Holder ()))));
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
static void
gum_v8_core_on_native_pointer_to_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));
  gint radix = 16;
  bool radix_specified = info.Length () > 0;
  if (radix_specified)
    radix = info[0]->Int32Value ();
  if (radix != 10 && radix != 16)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "unsupported radix")));
    return;
  }

  gchar buf[32];
  if (radix == 10)
  {
    sprintf (buf, "%" G_GSIZE_MODIFIER "u", ptr);
  }
  else
  {
    if (radix_specified)
      sprintf (buf, "%" G_GSIZE_MODIFIER "x", ptr);
    else
      sprintf (buf, "0x%" G_GSIZE_MODIFIER "x", ptr);
  }

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_native_pointer_to_json (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar buf[32];
  sprintf (buf, "0x%" G_GSIZE_MODIFIER "x", ptr);

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (buf)));
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
static void
gum_v8_core_on_native_pointer_to_match_pattern (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

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

  info.GetReturnValue ().Set (String::NewFromOneByte (isolate,
      reinterpret_cast<const uint8_t *> (result)));
}

static void
gum_v8_core_on_new_native_function (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;
  GumFFIFunction * func;
  Local<Value> rtype_value;
  ffi_type * rtype;
  Local<Value> atypes_value;
  Local<Array> atypes_array;
  uint32_t nargs_fixed, nargs_total, i;
  gboolean is_variadic;
  ffi_abi abi;
  Local<Object> instance;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new NativeFunction()` to create a new instance")));
    return;
  }

  func = g_slice_new0 (GumFFIFunction);
  func->core = self;

  if (!_gum_v8_native_pointer_get (info[0], &func->fn, self))
    goto error;

  rtype_value = info[1];
  if (!gum_v8_ffi_type_get (self, rtype_value, &rtype, &func->data))
    goto error;

  atypes_value = info[2];
  if (!atypes_value->IsArray ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeFunction: third argument must be an array specifying "
        "argument types")));
    goto error;
  }
  atypes_array = atypes_value.As<Array> ();
  nargs_fixed = nargs_total = atypes_array->Length ();
  is_variadic = FALSE;
  func->atypes = g_new (ffi_type *, nargs_total);
  for (i = 0; i != nargs_total; i++)
  {
    Handle<Value> type (atypes_array->Get (i));
    String::Utf8Value type_utf (type);
    if (strcmp (*type_utf, "...") == 0)
    {
      if (is_variadic)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "NativeFunction: only one variadic marker may be "
            "specified")));
        goto error;
      }

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gum_v8_ffi_type_get (self, type,
        &func->atypes[is_variadic ? i - 1 : i], &func->data))
    {
      goto error;
    }
  }
  if (is_variadic)
    nargs_total--;

  abi = FFI_DEFAULT_ABI;
  if (info.Length () > 3)
  {
    if (!gum_v8_ffi_abi_get (self, info[3], &abi))
      goto error;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "NativeFunction: failed to compile function call "
          "interface")));
      goto error;
    }
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "NativeFunction: failed to compile function call "
          "interface")));
      goto error;
    }
  }

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  instance = info.Holder ();
  instance->SetInternalField (0, External::New (isolate, func->fn));
  instance->SetAlignedPointerInInternalField (1, func);

  func->weak_instance = new GumPersistent<Object>::type (isolate, instance);
  func->weak_instance->SetWeak (func, gum_ffi_function_on_weak_notify,
      WeakCallbackType::kParameter);
  func->weak_instance->MarkIndependent ();

  g_hash_table_insert (self->native_functions, func, func);

  return;

error:
  gum_ffi_function_free (func);
}

static void
gum_ffi_function_on_weak_notify (
    const WeakCallbackInfo<GumFFIFunction> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumFFIFunction * self = info.GetParameter ();
  g_hash_table_remove (self->core->native_functions, self);
}

static void
gum_v8_core_on_invoke_native_function (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;
  Local<Object> instance = info.Holder ();
  GumFFIFunction * func = static_cast<GumFFIFunction *> (
      instance->GetAlignedPointerFromInternalField (1));
  gsize nargs = func->cif.nargs;
  GumExceptorScope scope;

  if (info.Length () != static_cast<int> (nargs))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeFunction: bad argument count")));
    return;
  }

  ffi_type * rtype = func->cif.rtype;

  gsize rsize = MAX (rtype->size, sizeof (gsize));
  gsize ralign = MAX (rtype->alignment, sizeof (gsize));
  GumFFIValue * rvalue = (GumFFIValue *) g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  void ** avalue;
  guint8 * avalues;

  if (nargs > 0)
  {
    avalue = (void **) g_alloca (nargs * sizeof (void *));

    gsize arglist_alignment = func->cif.arg_types[0]->alignment;
    avalues = (guint8 *) g_alloca (func->arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, func->arglist_size);

    gsize offset = 0;
    for (gsize i = 0; i != nargs; i++)
    {
      ffi_type * t = func->cif.arg_types[i];

      offset = GUM_ALIGN_SIZE (offset, t->alignment);

      GumFFIValue * v = (GumFFIValue *) (avalues + offset);

      if (!gum_v8_value_to_ffi_type (self, info[i], v, t))
        return;
      avalue[i] = v;

      offset += t->size;
    }
  }
  else
  {
    avalue = NULL;
  }

  self->isolate->Exit ();

  {
    Unlocker ul (self->isolate);

    if (gum_exceptor_try (self->exceptor, &scope))
    {
      ffi_call (&func->cif, FFI_FN (func->fn), rvalue, avalue);
    }
  }

  self->isolate->Enter ();

  if (gum_exceptor_catch (self->exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, self);
    return;
  }

  if (rtype != &ffi_type_void)
  {
    Local<Value> result;
    if (!gum_v8_value_from_ffi_type (self, &result, rvalue, rtype))
      return;

    info.GetReturnValue ().Set (result);
  }
}

static void
gum_ffi_function_free (GumFFIFunction * func)
{
  delete func->weak_instance;

  while (func->data != NULL)
  {
    GSList * head = func->data;
    g_free (head->data);
    func->data = g_slist_delete_link (func->data, head);
  }
  g_free (func->atypes);

  g_slice_free (GumFFIFunction, func);
}

static void
gum_v8_core_on_new_native_callback (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;
  GumFFICallback * callback;
  Local<Value> func_value;
  Local<Value> rtype_value;
  ffi_type * rtype;
  Local<Value> atypes_value;
  Local<Array> atypes_array;
  uint32_t nargs, i;
  ffi_abi abi;
  gpointer func = NULL;
  Local<Object> instance;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new NativeCallback()` to create a new instance")));
    return;
  }

  callback = g_slice_new0 (GumFFICallback);
  callback->core = self;

  func_value = info[0];
  if (!func_value->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: first argument must be a function implementing "
        "the callback")));
    goto error;
  }
  callback->func = new GumPersistent<Function>::type (isolate,
      func_value.As<Function> ());

  rtype_value = info[1];
  if (!rtype_value->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: second argument must be a string specifying "
        "return type")));
    goto error;
  }
  if (!gum_v8_ffi_type_get (self, rtype_value, &rtype, &callback->data))
    goto error;

  atypes_value = info[2];
  if (!atypes_value->IsArray ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: third argument must be an array specifying "
        "argument types")));
    goto error;
  }
  atypes_array = atypes_value.As<Array> ();
  nargs = atypes_array->Length ();
  callback->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    if (!gum_v8_ffi_type_get (self, atypes_array->Get (i),
        &callback->atypes[i], &callback->data))
    {
      goto error;
    }
  }

  abi = FFI_DEFAULT_ABI;
  if (info.Length () > 3)
  {
    if (!gum_v8_ffi_abi_get (self, info[3], &abi))
      goto error;
  }

  callback->closure = static_cast<ffi_closure *> (
      ffi_closure_alloc (sizeof (ffi_closure), &func));
  if (callback->closure == NULL)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: failed to allocate closure")));
    goto error;
  }

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
        callback->atypes) != FFI_OK)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: failed to compile function call interface")));
    goto error;
  }

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
        gum_v8_core_on_invoke_native_callback, callback, func) != FFI_OK)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: failed to prepare closure")));
    goto error;
  }

  instance = info.Holder ();
  instance->SetInternalField (0, External::New (isolate, func));

  callback->weak_instance = new GumPersistent<Object>::type (isolate, instance);
  callback->weak_instance->SetWeak (callback,
      gum_v8_core_on_free_native_callback, WeakCallbackType::kParameter);
  callback->weak_instance->MarkIndependent ();

  g_hash_table_insert (self->native_callbacks, callback, callback);

  return;

error:
  gum_ffi_callback_free (callback);
}

static void
gum_v8_core_on_free_native_callback (
    const WeakCallbackInfo<GumFFICallback> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumFFICallback * self = info.GetParameter ();
  g_hash_table_remove (self->core->native_callbacks, self);
}

static void
gum_v8_core_on_invoke_native_callback (ffi_cif * cif,
                                       void * return_value,
                                       void ** args,
                                       void * user_data)
{
  GumFFICallback * self = static_cast<GumFFICallback *> (user_data);
  ScriptScope scope (self->core->script);
  Isolate * isolate = self->core->isolate;

  ffi_type * rtype = cif->rtype;
  GumFFIValue * retval = (GumFFIValue *) return_value;
  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  Local<Value> * argv = static_cast<Local<Value> *> (
      g_alloca (cif->nargs * sizeof (Local<Value>)));
  for (guint i = 0; i != cif->nargs; i++)
  {
    if (!gum_v8_value_from_ffi_type (self->core, &argv[i],
        (GumFFIValue *) args[i], cif->arg_types[i]))
    {
      for (guint j = 0; j != i; j++)
        argv[j].~Local<Value> ();
      return;
    }
  }

  Local<Function> func (Local<Function>::New (isolate, *self->func));

  Local<Value> receiver;
  GumInvocationContext * ic = gum_interceptor_get_current_invocation ();
  if (ic != NULL)
  {
    receiver = _gum_v8_interceptor_create_invocation_context_object (
        &self->core->script->priv->interceptor, ic);
  }
  else
  {
    receiver = Undefined (isolate);
  }

  Local<Value> result = func->Call (receiver, cif->nargs, argv);

  if (ic != NULL)
  {
    _gum_v8_interceptor_detach_cpu_context (
        &self->core->script->priv->interceptor, receiver);
  }

  if (cif->rtype != &ffi_type_void)
  {
    if (!scope.HasPendingException ())
      gum_v8_value_to_ffi_type (self->core, result, retval, cif->rtype);
  }

  for (guint i = 0; i != cif->nargs; i++)
    argv[i].~Local<Value> ();
}

static void
gum_ffi_callback_free (GumFFICallback * callback)
{
  delete callback->weak_instance;

  delete callback->func;

  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    GSList * head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);

  g_slice_free (GumFFICallback, callback);
}

static void
gum_v8_core_on_new_cpu_context (const FunctionCallbackInfo<Value> & info)
{
  GumV8Core * self = static_cast<GumV8Core *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  if (info.Length () < 2 || !info[0]->IsExternal () || !info[1]->IsBoolean ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "CpuContext: invalid argument")));
    return;
  }

  Local<Object> instance = info.Holder ();
  instance->SetInternalField (0, info[0]);
  instance->SetInternalField (1, info[1]);
  instance->SetAlignedPointerInInternalField (2, self);
}

static void
gum_v8_core_on_cpu_context_get_register (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  Local<Object> instance = info.Holder ();
  GumV8Core * self = static_cast<GumV8Core *> (
      instance->GetAlignedPointerFromInternalField (2));
  gpointer * cpu_context = static_cast<gpointer *> (
      instance->GetInternalField (0).As<External> ()->Value ());
  gsize offset = info.Data ().As<Integer> ()->Value ();

  (void) property;

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (cpu_context[offset], self));
}

static void
gum_v8_core_on_cpu_context_set_register (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  Isolate * isolate = info.GetIsolate ();
  Local<Object> instance = info.Holder ();
  GumV8Core * self = static_cast<GumV8Core *> (
      instance->GetAlignedPointerFromInternalField (2));
  gssize * cpu_context = static_cast<gssize *> (
      instance->GetInternalField (0).As<External> ()->Value ());
  bool is_mutable = instance->GetInternalField (1).As<Boolean> ()->Value ();
  gsize offset = info.Data ().As<Integer> ()->Value ();

  (void) property;

  if (!is_mutable)
  {
    isolate->ThrowException (Exception::TypeError (
        String::NewFromUtf8 (isolate, "this CpuContext is not mutable")));
    return;
  }

  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (isolate,
      *self->native_pointer));
  gssize raw_value;
  if (native_pointer->HasInstance (value))
  {
    raw_value = reinterpret_cast<gssize> (
        GUMJS_NATIVE_POINTER_VALUE (value.As<Object> ()));
  }
  else
  {
    raw_value = value->ToInteger ()->Value ();
  }

  cpu_context[offset] = raw_value;
}

static GumV8ExceptionSink *
gum_v8_exception_sink_new (Handle<Function> callback,
                           Isolate * isolate)
{
  GumV8ExceptionSink * sink;

  sink = g_slice_new (GumV8ExceptionSink);
  sink->callback = new GumPersistent<Function>::type (isolate, callback);
  sink->isolate = isolate;

  return sink;
}

static void
gum_v8_exception_sink_free (GumV8ExceptionSink * sink)
{
  if (sink == NULL)
    return;

  delete sink->callback;

  g_slice_free (GumV8ExceptionSink, sink);
}

static void
gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
                                        Handle<Value> exception)
{
  Isolate * isolate = self->isolate;
  Handle<Value> argv[] = { exception };

  Local<Function> callback (Local<Function>::New (isolate, *self->callback));
  callback->Call (Null (isolate), 1, argv);
}

static GumV8MessageSink *
gum_v8_message_sink_new (Handle<Function> callback,
                         Isolate * isolate)
{
  GumV8MessageSink * sink;

  sink = g_slice_new (GumV8MessageSink);
  sink->callback = new GumPersistent<Function>::type (isolate, callback);
  sink->isolate = isolate;

  return sink;
}

static void
gum_v8_message_sink_free (GumV8MessageSink * sink)
{
  if (sink == NULL)
    return;

  delete sink->callback;

  g_slice_free (GumV8MessageSink, sink);
}

static void
gum_v8_message_sink_handle_message (GumV8MessageSink * self,
                                    const gchar * message)
{
  Isolate * isolate = self->isolate;
  Handle<Value> argv[] = { String::NewFromUtf8 (isolate, message) };

  Local<Function> callback (Local<Function>::New (isolate, *self->callback));
  callback->Call (Null (isolate), 1, argv);
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
  if (name->IsString ())
  {
    String::Utf8Value str_value (name);
    const gchar * str = *str_value;
    for (guint i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
    {
      const GumFFITypeMapping * m = &gum_ffi_type_mappings[i];
      if (strcmp (str, m->name) == 0)
      {
        *type = m->type;
        return TRUE;
      }
    }
  }
  else if (name->IsArray ())
  {
    Isolate * isolate = core->isolate;
    Local<Context> context = isolate->GetCurrentContext ();

    Local<Array> fields_value = Handle<Array>::Cast (name);
    gsize length = fields_value->Length ();

    ffi_type ** fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

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
        isolate->ThrowException (Exception::TypeError (
            String::NewFromUtf8 (isolate, "invalid field type specified")));
        return FALSE;
      }
    }

    fields[length] = NULL;

    ffi_type * struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    return TRUE;
  }

  core->isolate->ThrowException (Exception::TypeError (
      String::NewFromUtf8 (core->isolate, "invalid type specified")));
  return FALSE;
}

static gboolean
gum_v8_ffi_abi_get (GumV8Core * core,
                    Handle<Value> name,
                    ffi_abi * abi)
{
  String::Utf8Value str_value (name);
  const gchar * str = *str_value;
  for (guint i = 0; i != G_N_ELEMENTS (gum_ffi_abi_mappings); i++)
  {
    const GumFFIABIMapping * m = &gum_ffi_abi_mappings[i];
    if (strcmp (str, m->name) == 0)
    {
      *abi = m->abi;
      return TRUE;
    }
  }

  core->isolate->ThrowException (Exception::TypeError (
      String::NewFromUtf8 (core->isolate, "invalid abi specified")));
  return FALSE;
}

static gboolean
gum_v8_value_to_ffi_type (GumV8Core * core,
                          const Handle<Value> svalue,
                          GumFFIValue * value,
                          const ffi_type * type)
{
  Isolate * isolate = core->isolate;

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
    value->v_sint8 = static_cast<gint8> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint8)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint8 = static_cast<guint8> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_sint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint16 = static_cast<gint16> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint16 = static_cast<guint16> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_sint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint32 = static_cast<gint32> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint32 = static_cast<guint32> (svalue->Uint32Value ());
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
    Local<Context> context = isolate->GetCurrentContext ();
    const ffi_type * const * field_types = type->elements;

    if (!svalue->IsArray ())
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "expected array with fields")));
      return FALSE;
    }
    Local<Array> field_svalues = Handle<Array>::Cast (svalue);

    gsize provided_length = field_svalues->Length ();
    gsize length = 0;
    for (const ffi_type * const * t = field_types; *t != NULL; t++)
      length++;
    if (provided_length != length)
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "provided array length does not match number of fields")));
      return FALSE;
    }

    guint8 * field_values = (guint8 *) value;
    gsize offset = 0;
    for (gsize i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      GumFFIValue * field_value =
          (GumFFIValue *) (field_values + offset);
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
        isolate->ThrowException (Exception::TypeError (
            String::NewFromUtf8 (isolate, "invalid field value specified")));
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
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "expected number")));
    return FALSE;
  }
error_unsupported_type:
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "unsupported type")));
    return FALSE;
  }
}

static gboolean
gum_v8_value_from_ffi_type (GumV8Core * core,
                            Handle<Value> * svalue,
                            const GumFFIValue * value,
                            const ffi_type * type)
{
  Isolate * isolate = core->isolate;

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
    const ffi_type * const * field_types = type->elements;

    gsize length = 0;
    for (const ffi_type * const * t = field_types; *t != NULL; t++)
      length++;

    Local<Array> field_svalues = Array::New (isolate, length);
    const guint8 * field_values = (const guint8 *) value;
    gsize offset = 0;
    for (gsize i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      const GumFFIValue * field_value =
          (const GumFFIValue *) (field_values + offset);
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
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "unsupported type")));
    return FALSE;
  }

  return TRUE;
}

GBytes *
_gum_v8_byte_array_get (Handle<Value> value,
                        GumV8Core * core)
{
  GBytes * result = _gum_v8_byte_array_try_get (value, core);
  if (result == NULL)
  {
    core->isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        core->isolate, "unsupported data value")));
    return NULL;
  }

  return result;
}

GBytes *
_gum_v8_byte_array_try_get (Handle<Value> value,
                            GumV8Core * core)
{
  if (value->IsArrayBuffer ())
  {
    ArrayBuffer::Contents contents =
        Handle<ArrayBuffer>::Cast (value)->GetContents ();

    return g_bytes_new (contents.Data (), contents.ByteLength ());
  }
  else if (value->IsArray ())
  {
    Handle<Array> array = Handle<Array>::Cast (value);

    gsize data_length = array->Length ();
    if (data_length > GUM_MAX_SEND_ARRAY_LENGTH)
      return NULL;

    Local<Context> context = core->isolate->GetCurrentContext ();

    guint8 * data = (guint8 *) g_malloc (data_length);
    gboolean data_valid = TRUE;

    for (guint i = 0; i != data_length && data_valid; i++)
    {
      gboolean element_valid = FALSE;

      Local<Value> element_value;
      if (array->Get (context, i).ToLocal (&element_value))
      {
        Maybe<uint32_t> element = element_value->Uint32Value (context);
        if (element.IsJust ())
        {
          data[i] = element.FromJust ();
          element_valid = TRUE;
        }
      }

      if (!element_valid)
        data_valid = FALSE;
    }

    if (!data_valid)
    {
      g_free (data);
      return NULL;
    }

    return g_bytes_new_take (data, data_length);
  }

  return NULL;
}

GumV8NativeResource *
_gum_v8_native_resource_new (gpointer data,
                             gsize size,
                             GDestroyNotify notify,
                             GumV8Core * core)
{
  GumV8NativeResource * resource;

  resource = g_slice_new (GumV8NativeResource);
  resource->instance = new GumPersistent<Object>::type (core->isolate,
      _gum_v8_native_pointer_new (data, core));
  resource->instance->MarkIndependent ();
  resource->instance->SetWeak (resource, gum_v8_native_resource_on_weak_notify,
      WeakCallbackType::kParameter);
  resource->data = data;
  resource->size = size;
  resource->notify = notify;
  resource->core = core;

  core->isolate->AdjustAmountOfExternalAllocatedMemory (size);

  g_hash_table_insert (core->native_resources, resource, resource);

  return resource;
}

void
_gum_v8_native_resource_free (GumV8NativeResource * resource)
{
  resource->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -static_cast<gssize> (resource->size));

  delete resource->instance;
  if (resource->notify != NULL)
    resource->notify (resource->data);
  g_slice_free (GumV8NativeResource, resource);
}

static void
gum_v8_native_resource_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeResource> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumV8NativeResource * self = info.GetParameter ();
  g_hash_table_remove (self->core->native_resources, self);
}

gboolean
_gum_v8_size_get (Handle<Value> value,
                  gsize * target,
                  GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    int64_t integer_value = value->IntegerValue ();
    if (integer_value >= 0)
    {
      *target = (gsize) integer_value;
      return TRUE;
    }
  }
  else
  {
    Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (isolate,
        *core->uint64));
    if (uint64->HasInstance (value))
    {
      *target = (gsize) gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }

    Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
        isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      gint64 int64_value = gum_v8_int64_get_value (value.As<Object> ());
      if (int64_value >= 0)
      {
        *target = (gsize) int64_value;
        return TRUE;
      }
    }
  }

  isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
      isolate, "expected an unsigned integer")));
  return FALSE;
}

gboolean
_gum_v8_ssize_get (Handle<Value> value,
                   gssize * target,
                   GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = (gssize) value->IntegerValue ();
    return TRUE;
  }
  else
  {
    Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
        isolate, *core->int64));
    if (int64->HasInstance (value))
    {
      *target = (gssize) gum_v8_int64_get_value (value.As<Object> ());
      return TRUE;
    }

    Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (isolate,
        *core->uint64));
    if (uint64->HasInstance (value))
    {
      *target = (gssize) gum_v8_uint64_get_value (value.As<Object> ());
      return TRUE;
    }
  }

  isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
      isolate, "expected an integer")));
  return FALSE;
}

Local<Object>
_gum_v8_int64_new (gint64 value,
                   GumV8Core * core)
{
  Local<Object> int64_value (Local<Object>::New (core->isolate,
      *core->int64_value));
  Local<Object> int64_object (int64_value->Clone ());
  gum_v8_int64_set_value (int64_object, value, core->isolate);
  return int64_object;
}

gboolean
_gum_v8_int64_get (Handle<Value> value,
                   gint64 * target,
                   GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = value->IntegerValue ();
    return TRUE;
  }

  Local<FunctionTemplate> int64 (Local<FunctionTemplate>::New (
      isolate, *core->int64));
  if (!int64->HasInstance (value))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected an integer")));
    return FALSE;
  }

  *target = gum_v8_int64_get_value (value.As<Object> ());
  return TRUE;
}

Local<Object>
_gum_v8_uint64_new (guint64 value,
                    GumV8Core * core)
{
  Local<Object> uint64_value (Local<Object>::New (core->isolate,
      *core->uint64_value));
  Local<Object> uint64_object (uint64_value->Clone ());
  gum_v8_uint64_set_value (uint64_object, value, core->isolate);
  return uint64_object;
}

static gint64
gum_v8_int64_get_value (Handle<Object> object)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gpointer p;
    gint64 i;
  } v;

  v.p = object->GetInternalField (0).As<External> ()->Value ();

  return v.i;
#else
  union
  {
    gpointer p;
    guint32 bits;
  } upper, lower;
  union
  {
    guint64 bits;
    gint64 i;
  } v;

  upper.p = object->GetInternalField (0).As<External> ()->Value ();
  lower.p = object->GetInternalField (1).As<External> ()->Value ();

  v.bits = static_cast<guint64> (upper.bits) << 32 |
      static_cast<guint64> (lower.bits);

  return v.i;
#endif
}

static void
gum_v8_int64_set_value (Handle<Object> object,
                        gint64 value,
                        Isolate * isolate)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gint64 i;
    gpointer p;
  } v;

  v.i = value;

  object->SetInternalField (0, External::New (isolate, v.p));
#else
  union
  {
    gint64 i;
    guint64 bits;
  } v;
  union
  {
    guint32 bits;
    gpointer p;
  } upper, lower;

  v.i = value;

  upper.bits = v.bits >> 32;
  lower.bits = v.bits & 0xffffffff;

  object->SetInternalField (0, External::New (isolate, upper.p));
  object->SetInternalField (1, External::New (isolate, lower.p));
#endif
}

gboolean
_gum_v8_uint64_get (Handle<Value> value,
                    guint64 * target,
                    GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsNumber ())
  {
    *target = value->IntegerValue ();
    return TRUE;
  }

  Local<FunctionTemplate> uint64 (Local<FunctionTemplate>::New (
      isolate, *core->uint64));
  if (!uint64->HasInstance (value))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected an unsigned integer")));
    return FALSE;
  }

  *target = gum_v8_uint64_get_value (value.As<Object> ());
  return TRUE;
}

static guint64
gum_v8_uint64_get_value (Handle<Object> object)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    gpointer p;
    guint64 u;
  } v;

  v.p = object->GetInternalField (0).As<External> ()->Value ();

  return v.u;
#else
  union
  {
    gpointer p;
    guint32 bits;
  } upper, lower;

  upper.p = object->GetInternalField (0).As<External> ()->Value ();
  lower.p = object->GetInternalField (1).As<External> ()->Value ();

  return static_cast<guint64> (upper.bits) << 32 |
      static_cast<guint64> (lower.bits);
#endif
}

static void
gum_v8_uint64_set_value (Handle<Object> object,
                         guint64 value,
                         Isolate * isolate)
{
#if GLIB_SIZEOF_VOID_P == 8
  union
  {
    guint64 u;
    gpointer p;
  } v;

  v.u = value;

  object->SetInternalField (0, External::New (isolate, v.p));
#else
  union
  {
    guint32 bits;
    gpointer p;
  } upper, lower;

  upper.bits = value >> 32;
  lower.bits = value & 0xffffffff;

  object->SetInternalField (0, External::New (isolate, upper.p));
  object->SetInternalField (1, External::New (isolate, lower.p));
#endif
}

Local<Object>
_gum_v8_native_pointer_new (gpointer address,
                            GumV8Core * core)
{
  Local<Object> native_pointer_value (Local<Object>::New (core->isolate,
      *core->native_pointer_value));
  Local<Object> native_pointer_object (native_pointer_value->Clone ());
  native_pointer_object->SetInternalField (0,
      External::New (core->isolate, address));
  return native_pointer_object;
}

gboolean
_gum_v8_native_pointer_get (Handle<Value> value,
                            gpointer * target,
                            GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  gboolean success = FALSE;

  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (
      isolate, *core->native_pointer));
  if (native_pointer->HasInstance (value))
  {
    *target = GUMJS_NATIVE_POINTER_VALUE (value.As<Object> ());
    success = TRUE;
  }
  else
  {
    /* Cannot use isObject() here as that returns false for proxies */
    MaybeLocal<Object> maybe_obj;
    {
      TryCatch trycatch (isolate);
      maybe_obj = value->ToObject (isolate);
      trycatch.Reset ();
    }

    Local<Object> obj;
    if (maybe_obj.ToLocal (&obj))
    {
      Local<Context> context = isolate->GetCurrentContext ();
      Local<String> handle_key (Local<String>::New (isolate,
          *core->handle_key));
      if (obj->Has (context, handle_key).FromJust ())
      {
        Local<Value> handle = obj->Get (context, handle_key).ToLocalChecked ();
        if (native_pointer->HasInstance (handle))
        {
          *target = GUMJS_NATIVE_POINTER_VALUE (handle.As<Object> ());
          success = TRUE;
        }
      }
    }
  }

  if (!success)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected NativePointer object")));
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_v8_native_pointer_parse (Handle<Value> value,
                              gpointer * target,
                              GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (value->IsString ())
  {
    String::Utf8Value ptr_as_utf8 (value);
    const gchar * ptr_as_string = *ptr_as_utf8;
    gchar * endptr;
    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      *target = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string + 2, &endptr, 16));
      if (endptr == ptr_as_string + 2)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "invalid hexadecimal string")));
        return FALSE;
      }
    }
    else
    {
      *target = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string, &endptr, 10));
      if (endptr == ptr_as_string)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "invalid decimal string")));
        return FALSE;
      }
    }

    return TRUE;
  }
  else if (value->IsNumber ())
  {
    *target = GSIZE_TO_POINTER (value.As<Number> ()->Value ());
    return TRUE;
  }

  return _gum_v8_native_pointer_get (value, target, core);
}

void
_gum_v8_throw_native (GumExceptionDetails * details,
                      GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);
  _gum_v8_cpu_context_free_later (
      new GumPersistent<Object>::type (isolate, context),
      core);
  isolate->ThrowException (ex);
}

void
_gum_v8_parse_exception_details (GumExceptionDetails * details,
                                 Local<Object> & exception,
                                 Local<Object> & cpu_context,
                                 GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  gchar * message = gum_exception_details_to_string (details);
  Local<Object> ex =
      Exception::Error (String::NewFromUtf8 (isolate, message)).As<Object> ();
  g_free (message);

  _gum_v8_object_set_ascii (ex, "type",
      gum_exception_type_to_string (details->type), core);
  _gum_v8_object_set_pointer (ex, "address", details->address, core);

  const GumExceptionMemoryDetails * md = &details->memory;
  if (md->operation != GUM_MEMOP_INVALID)
  {
    Local<Object> memory (Object::New (isolate));
    _gum_v8_object_set_ascii (memory, "operation",
        _gum_v8_memory_operation_to_string (md->operation), core);
    _gum_v8_object_set_pointer (memory, "address", md->address, core);
    _gum_v8_object_set (ex, "memory", memory, core);
  }

  Local<Object> context = _gum_v8_cpu_context_new (&details->context, core);
  _gum_v8_object_set (ex, "context", context, core);
  _gum_v8_object_set_pointer (ex, "nativeContext", details->native_context, core);

  exception = ex;
  cpu_context = context;
}

static const gchar *
gum_exception_type_to_string (GumExceptionType type)
{
  switch (type)
  {
    case GUM_EXCEPTION_ABORT: return "abort";
    case GUM_EXCEPTION_ACCESS_VIOLATION: return "access-violation";
    case GUM_EXCEPTION_GUARD_PAGE: return "guard-page";
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal-instruction";
    case GUM_EXCEPTION_STACK_OVERFLOW: return "stack-overflow";
    case GUM_EXCEPTION_ARITHMETIC: return "arithmetic";
    case GUM_EXCEPTION_BREAKPOINT: return "breakpoint";
    case GUM_EXCEPTION_SINGLE_STEP: return "single-step";
    case GUM_EXCEPTION_SYSTEM: return "system";
    default:
      break;
  }

  g_assert_not_reached ();
}

v8::Local<v8::Object>
_gum_v8_cpu_context_new (const GumCpuContext * cpu_context,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Local<Object> cpu_context_value (Local<Object>::New (isolate,
      *core->cpu_context_value));
  Local<Object> cpu_context_object (cpu_context_value->Clone ());
  cpu_context_object->SetInternalField (0,
      External::New (isolate, const_cast<GumCpuContext *> (cpu_context)));
  const bool is_mutable = false;
  cpu_context_object->SetInternalField (1, Boolean::New (isolate, is_mutable));
  return cpu_context_object;
}

v8::Local<v8::Object>
_gum_v8_cpu_context_new (GumCpuContext * cpu_context,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Local<Object> cpu_context_value (Local<Object>::New (isolate,
      *core->cpu_context_value));
  Local<Object> cpu_context_object (cpu_context_value->Clone ());
  cpu_context_object->SetInternalField (0,
      External::New (isolate, cpu_context));
  const bool is_mutable = true;
  cpu_context_object->SetInternalField (1, Boolean::New (isolate, is_mutable));
  return cpu_context_object;
}

void
_gum_v8_cpu_context_free_later (GumPersistent<Object>::type * cpu_context,
                                GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  GumCpuContextWrapper * wrapper;

  Local<Object> instance (Local<Object>::New (isolate, *cpu_context));
  GumCpuContext * original = static_cast<GumCpuContext *> (
      instance->GetInternalField (0).As<External> ()->Value ());
  GumCpuContext * copy = g_slice_dup (GumCpuContext, original);
  instance->SetInternalField (0, External::New (isolate, copy));
  const bool is_mutable = false;
  instance->SetInternalField (1, Boolean::New (isolate, is_mutable));

  wrapper = g_slice_new (GumCpuContextWrapper);
  wrapper->instance = cpu_context;
  wrapper->cpu_context = copy;

  cpu_context->SetWeak (wrapper, gum_cpu_context_on_weak_notify,
      WeakCallbackType::kParameter);
  cpu_context->MarkIndependent ();
}

static void
gum_cpu_context_on_weak_notify (
    const WeakCallbackInfo<GumCpuContextWrapper> & info)
{
  GumCpuContextWrapper * wrapper = info.GetParameter ();

  delete wrapper->instance;

  g_slice_free (GumCpuContext, wrapper->cpu_context);

  g_slice_free (GumCpuContextWrapper, wrapper);
}

gboolean
_gum_v8_cpu_context_get (v8::Handle<v8::Value> value,
                         GumCpuContext ** target,
                         GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<FunctionTemplate> cpu_context (Local<FunctionTemplate>::New (
      isolate, *core->cpu_context));
  if (!cpu_context->HasInstance (value))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected CpuContext object")));
    return FALSE;
  }
  *target = GUMJS_CPU_CONTEXT_VALUE (value.As<Object> ());

  return TRUE;
}

const gchar *
_gum_v8_thread_state_to_string (GumThreadState state)
{
  switch (state)
  {
    case GUM_THREAD_RUNNING: return "running";
    case GUM_THREAD_STOPPED: return "stopped";
    case GUM_THREAD_WAITING: return "waiting";
    case GUM_THREAD_UNINTERRUPTIBLE: return "uninterruptible";
    case GUM_THREAD_HALTED: return "halted";
    default:
      break;
  }

  g_assert_not_reached ();
}

const gchar *
_gum_v8_memory_operation_to_string (GumMemoryOperation operation)
{
  switch (operation)
  {
    case GUM_MEMOP_INVALID: return "invalid";
    case GUM_MEMOP_READ: return "read";
    case GUM_MEMOP_WRITE: return "write";
    case GUM_MEMOP_EXECUTE: return "execute";
    default:
      g_assert_not_reached ();
  }
}

gboolean
_gum_v8_object_set (Handle<Object> object,
                    const gchar * key,
                    Handle<Value> value,
                    GumV8Core * core)
{
  Isolate * isolate = core->isolate;
  Maybe<bool> success = object->Set (isolate->GetCurrentContext (),
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> (key)),
      value);
  return success.IsJust ();
}

gboolean
_gum_v8_object_set_uint (Handle<Object> object,
                         const gchar * key,
                         guint value,
                         GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      Integer::NewFromUnsigned (core->isolate, value),
      core);
}

gboolean
_gum_v8_object_set_pointer (Handle<Object> object,
                            const gchar * key,
                            gpointer value,
                            GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      _gum_v8_native_pointer_new (value, core),
      core);
}

gboolean
_gum_v8_object_set_pointer (Handle<Object> object,
                            const gchar * key,
                            GumAddress value,
                            GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (value), core),
      core);
}

gboolean
_gum_v8_object_set_ascii (Handle<Object> object,
                          const gchar * key,
                          const gchar * value,
                          GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      String::NewFromOneByte (core->isolate,
          reinterpret_cast<const uint8_t *> (value)),
      core);
}

gboolean
_gum_v8_object_set_utf8 (Handle<Object> object,
                         const gchar * key,
                         const gchar * value,
                         GumV8Core * core)
{
  return _gum_v8_object_set (object,
      key,
      String::NewFromUtf8 (core->isolate, value),
      core);
}

gboolean
_gum_v8_callbacks_get (Handle<Object> callbacks,
                       const gchar * name,
                       Handle<Function> * callback_function,
                       GumV8Core * core)
{
  if (!_gum_v8_callbacks_get_opt (callbacks, name, callback_function, core))
    return FALSE;

  if ((*callback_function).IsEmpty ())
  {
    gchar * message = g_strdup_printf ("%s callback is required", name);
    core->isolate->ThrowException (Exception::TypeError (
        String::NewFromUtf8 (core->isolate, message)));
    g_free (message);

    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_v8_callbacks_get_opt (Handle<Object> callbacks,
                           const gchar * name,
                           Handle<Function> * callback_function,
                           GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  Local<Value> val = callbacks->Get (String::NewFromUtf8 (isolate, name));
  if (!val->IsUndefined ())
  {
    if (!val->IsFunction ())
    {
      gchar * message = g_strdup_printf ("%s must be a function", name);
      isolate->ThrowException (Exception::TypeError (
          String::NewFromUtf8 (isolate, message)));
      g_free (message);

      return FALSE;
    }

    *callback_function = Local<Function>::Cast (val);
  }

  return TRUE;
}

gboolean
_gum_v8_page_protection_get (Handle<Value> prot_val,
                             GumPageProtection * prot,
                             GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  if (!prot_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "argument must be a string specifying memory protection")));
    return FALSE;
  }
  String::Utf8Value prot_str (prot_val);

  *prot = GUM_PAGE_NO_ACCESS;
  for (const gchar * ch = *prot_str; *ch != '\0'; ch++)
  {
    switch (*ch)
    {
      case 'r':
        *prot |= GUM_PAGE_READ;
        break;
      case 'w':
        *prot |= GUM_PAGE_WRITE;
        break;
      case 'x':
        *prot |= GUM_PAGE_EXECUTE;
        break;
      case '-':
        break;
      default:
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "invalid character in memory protection "
            "specifier string")));
        return FALSE;
    }
  }

  return TRUE;
}
