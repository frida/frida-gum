/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptcore.h"

#include "gumscriptscope.h"

#include <ffi.h>
#include <string.h>

#define GUM_SCRIPT_CORE_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_SCRIPT_CORE_UNLOCK() (g_mutex_unlock (&self->mutex))

using namespace v8;

typedef struct _GumWeakRef GumWeakRef;
typedef struct _GumFFIFunction GumFFIFunction;
typedef struct _GumFFICallback GumFFICallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumWeakRef
{
  gint id;
  GumPersistent<Value>::type * target;
  GumPersistent<Function>::type * callback;
  GumScriptCore * core;
};

struct _GumScheduledCallback
{
  gint id;
  gboolean repeat;
  GumPersistent<Function>::type * func;
  GumPersistent<Value>::type * receiver;
  GSource * source;
  GumScriptCore * core;
};

struct _GumMessageSink
{
  GumPersistent<Function>::type * callback;
  GumPersistent<Value>::type * receiver;
  Isolate * isolate;
};

struct _GumFFIFunction
{
  GumScriptCore * core;
  gpointer fn;
  ffi_cif cif;
  ffi_type ** atypes;
  GumPersistent<Object>::type * weak_instance;
};

struct _GumFFICallback
{
  GumScriptCore * core;
  GumPersistent<Function>::type * func;
  GumPersistent<Value>::type * receiver;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
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

static void gum_script_core_on_weak_ref_bind (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_weak_ref_unbind (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_clear_weak_ref_entry (gint id, GumWeakRef * ref);
static GumWeakRef * gum_weak_ref_new (gint id, Handle<Value> target,
    Handle<Function> callback, GumScriptCore * core);
static void gum_weak_ref_clear (GumWeakRef * ref);
static void gum_weak_ref_free (GumWeakRef * ref);
static void gum_weak_ref_on_weak_notify (const WeakCallbackData<Value,
    GumWeakRef> & data);
static void gum_script_core_on_set_timeout (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_set_interval (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_clear_timeout (
    const FunctionCallbackInfo<Value> & info);
static GumScheduledCallback * gum_scheduled_callback_new (gint id,
    gboolean repeat, GSource * source, GumScriptCore * core);
static void gum_scheduled_callback_free (GumScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);
static void gum_script_core_on_send (const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_set_incoming_message_callback (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_wait_for_event (
    const FunctionCallbackInfo<Value> & info);

static void gum_script_core_on_new_native_pointer (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_is_null (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_add (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_sub (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_and (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_or (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_xor (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_to_int32 (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_to_string (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_native_pointer_to_json (
    const FunctionCallbackInfo<Value> & info);

static void gum_script_core_on_new_native_function (
    const FunctionCallbackInfo<Value> & info);
static void gum_ffi_function_on_weak_notify (
    const WeakCallbackData<Object, GumFFIFunction> & data);
static void gum_script_core_on_invoke_native_function (
    const FunctionCallbackInfo<Value> & info);
static void gum_ffi_function_free (GumFFIFunction * func);

static void gum_script_core_on_new_native_callback (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_free_native_callback (
    const WeakCallbackData<Object, GumFFICallback> & data);
static void gum_script_core_on_invoke_native_callback (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);
static void gum_ffi_callback_free (GumFFICallback * callback);

static void gum_script_core_on_new_cpu_context (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_core_on_cpu_context_get_register (Local<String> property,
    const PropertyCallbackInfo<Value> & info);
static void gum_script_core_on_cpu_context_set_register (Local<String> property,
    Local<Value> value, const PropertyCallbackInfo<void> & info);

static GumMessageSink * gum_message_sink_new (Handle<Function> callback,
    Handle<Value> receiver, Isolate * isolate);
static void gum_message_sink_free (GumMessageSink * sink);
static void gum_message_sink_handle_message (GumMessageSink * self,
    const gchar * message);

static gboolean gum_script_ffi_type_get (GumScriptCore * core,
    Handle<Value> name, ffi_type ** type);
static gboolean gum_script_ffi_abi_get (GumScriptCore * core,
    Handle<Value> name, ffi_abi * abi);
static gboolean gum_script_value_to_ffi_type (GumScriptCore * core,
    const Handle<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_script_value_from_ffi_type (GumScriptCore * core,
    Handle<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

static void gum_byte_array_on_weak_notify (
    const WeakCallbackData<Object, GumByteArray> & data);
static void gum_heap_block_on_weak_notify (
    const WeakCallbackData<Object, GumHeapBlock> & data);

void
_gum_script_core_init (GumScriptCore * self,
                       GumScript * script,
                       GumScriptCoreMessageEmitter message_emitter,
                       GumScriptScheduler * scheduler,
                       v8::Isolate * isolate,
                       Handle<ObjectTemplate> scope)
{
  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->isolate = isolate;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->event_cond);

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_weak_ref_free));

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> frida = ObjectTemplate::New ();
  frida->Set (String::NewFromUtf8 (isolate, "version"),
      String::NewFromUtf8 (isolate, FRIDA_VERSION), ReadOnly);
  scope->Set (String::NewFromUtf8 (isolate, "Frida"), frida);

  Handle<ObjectTemplate> weak = ObjectTemplate::New ();
  weak->Set (String::NewFromUtf8 (isolate, "bind"),
      FunctionTemplate::New (isolate, gum_script_core_on_weak_ref_bind, data));
  weak->Set (String::NewFromUtf8 (isolate, "unbind"),
      FunctionTemplate::New (isolate, gum_script_core_on_weak_ref_unbind,
          data));
  scope->Set (String::NewFromUtf8 (isolate, "WeakRef"), weak);

  scope->Set (String::NewFromUtf8 (isolate, "setTimeout"),
      FunctionTemplate::New (isolate, gum_script_core_on_set_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "setInterval"),
      FunctionTemplate::New (isolate, gum_script_core_on_set_interval, data));
  scope->Set (String::NewFromUtf8 (isolate, "clearTimeout"),
      FunctionTemplate::New (isolate, gum_script_core_on_clear_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "clearInterval"),
      FunctionTemplate::New (isolate, gum_script_core_on_clear_timeout, data));
  scope->Set (String::NewFromUtf8 (isolate, "_send"),
      FunctionTemplate::New (isolate, gum_script_core_on_send, data));
  scope->Set (String::NewFromUtf8 (isolate, "_setIncomingMessageCallback"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_set_incoming_message_callback, data));
  scope->Set (String::NewFromUtf8 (isolate, "_waitForEvent"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_wait_for_event, data));

  Local<FunctionTemplate> native_pointer = FunctionTemplate::New (isolate,
      gum_script_core_on_new_native_pointer, data);
  native_pointer->SetClassName (
      String::NewFromUtf8 (isolate, "NativePointer"));
  Local<ObjectTemplate> native_pointer_proto =
      native_pointer->PrototypeTemplate ();
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "isNull"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_is_null));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "add"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_add, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "sub"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_sub, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "and"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_and, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "or"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_or, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "xor"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_xor, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toInt32"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_to_int32, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toString"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_to_string, data));
  native_pointer_proto->Set (String::NewFromUtf8 (isolate, "toJSON"),
      FunctionTemplate::New (isolate,
          gum_script_core_on_native_pointer_to_json, data));
  native_pointer->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "NativePointer"), native_pointer);
  self->native_pointer =
      new GumPersistent<FunctionTemplate>::type (isolate, native_pointer);

  Local<FunctionTemplate> native_function = FunctionTemplate::New (isolate,
      gum_script_core_on_new_native_function, data);
  native_function->SetClassName (
      String::NewFromUtf8 (isolate, "NativeFunction"));
  native_function->Inherit (native_pointer);
  Local<ObjectTemplate> native_function_object =
      native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gum_script_core_on_invoke_native_function, data);
  native_function_object->SetInternalFieldCount (2);
  scope->Set (String::NewFromUtf8 (isolate, "NativeFunction"),
      native_function);

  Local<FunctionTemplate> native_callback = FunctionTemplate::New (isolate,
      gum_script_core_on_new_native_callback, data);
  native_callback->SetClassName (
      String::NewFromUtf8 (isolate, "NativeCallback"));
  native_callback->Inherit (native_pointer);
  native_callback->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "NativeCallback"),
      native_callback);

  Local<FunctionTemplate> cpu_context = FunctionTemplate::New (isolate,
      gum_script_core_on_new_cpu_context, data);
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
      gum_script_core_on_cpu_context_get_register, \
      gum_script_core_on_cpu_context_set_register, \
      Integer::NewFromUnsigned (isolate, \
          G_STRUCT_OFFSET (GumCpuContext, R) / GLIB_SIZEOF_VOID_P), \
      DEFAULT, \
      static_cast<PropertyAttribute> (ReadOnly | DontDelete), \
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
_gum_script_core_realize (GumScriptCore * self)
{
  Isolate * isolate = self->isolate;
  Local<Context> context = isolate->GetCurrentContext ();

  self->native_functions = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_ffi_function_free));

  self->native_callbacks = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_ffi_callback_free));

  self->byte_arrays = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (_gum_byte_array_free));

  self->heap_blocks = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (_gum_heap_block_free));

  Local<FunctionTemplate> native_pointer (
      Local<FunctionTemplate>::New (isolate, *self->native_pointer));
  MaybeLocal<Object> maybe_native_pointer_value =
      native_pointer->GetFunction ()->NewInstance (context);
  Local<Object> native_pointer_value;
  bool success = maybe_native_pointer_value.ToLocal (&native_pointer_value);
  g_assert (success);
  self->native_pointer_value = new GumPersistent<Object>::type (isolate,
      native_pointer_value);

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

void
_gum_script_core_flush (GumScriptCore * self)
{
  self->isolate->Exit ();

  {
    Unlocker ul (self->isolate);

    gum_script_scheduler_flush_by_tag (self->scheduler, self);
  }

  self->isolate->Enter ();

  GMainContext * context =
      gum_script_scheduler_get_v8_context (self->scheduler);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);

  g_hash_table_foreach (self->weak_refs,
      (GHFunc) gum_script_core_clear_weak_ref_entry, NULL);
  g_hash_table_remove_all (self->weak_refs);
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  g_hash_table_unref (self->heap_blocks);
  self->heap_blocks = NULL;

  g_hash_table_unref (self->byte_arrays);
  self->byte_arrays = NULL;

  g_hash_table_unref (self->native_callbacks);
  self->native_callbacks = NULL;

  g_hash_table_unref (self->native_functions);
  self->native_functions = NULL;

  while (self->scheduled_callbacks != NULL)
  {
    g_source_destroy (static_cast<GumScheduledCallback *> (
        self->scheduled_callbacks->data)->source);
    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);
  }

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  delete self->native_pointer_value;
  self->native_pointer_value = NULL;

  delete self->cpu_context_value;
  self->cpu_context_value = NULL;
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  g_hash_table_unref (self->weak_refs);
  self->weak_refs = NULL;

  delete self->native_pointer;
  self->native_pointer = NULL;

  delete self->cpu_context;
  self->cpu_context = NULL;

  g_mutex_clear (&self->mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               const guint8 * data,
                               gint data_length)
{
  self->message_emitter (self->script, message, data, data_length);
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
  bool delivered = false;

  {
    Locker locker (self->isolate);

    if (self->incoming_message_sink != NULL)
    {
      ScriptScope scope (self->script);
      gum_message_sink_handle_message (self->incoming_message_sink, message);
      delivered = true;
    }
  }

  if (delivered)
  {
    GUM_SCRIPT_CORE_LOCK ();
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    GUM_SCRIPT_CORE_UNLOCK ();
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
gum_script_core_on_weak_ref_bind (const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
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

  gint id = g_atomic_int_add (&self->last_weak_ref_id, 1) + 1;

  ref = gum_weak_ref_new (id, target, callback_val.As <Function> (), self);
  g_hash_table_insert (self->weak_refs, GINT_TO_POINTER (id), ref);

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
gum_script_core_on_weak_ref_unbind (const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = info.GetIsolate ();

  Local<Value> id_val = info[0];
  if (!id_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "argument must be a weak ref id")));
    return;
  }
  gint id = id_val->ToInt32 ()->Value ();

  bool removed =
      !!g_hash_table_remove (self->weak_refs, GINT_TO_POINTER (id));

  info.GetReturnValue ().Set (removed);
}

static void
gum_script_core_clear_weak_ref_entry (gint id,
                                      GumWeakRef * ref)
{
  (void) id;

  gum_weak_ref_clear (ref);
}

static GumWeakRef *
gum_weak_ref_new (gint id,
                  Handle<Value> target,
                  Handle<Function> callback,
                  GumScriptCore * core)
{
  GumWeakRef * ref;
  Isolate * isolate = core->isolate;

  ref = g_slice_new (GumWeakRef);
  ref->id = id;
  ref->target = new GumPersistent<Value>::type (isolate, target);
  ref->target->SetWeak (ref, gum_weak_ref_on_weak_notify);
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
    ref->target->ClearWeak ();
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
gum_weak_ref_on_weak_notify (const WeakCallbackData<Value,
    GumWeakRef> & data)
{
  GumWeakRef * self = data.GetParameter ();

  g_hash_table_remove (self->core->weak_refs, GINT_TO_POINTER (self->id));
}

void
_gum_script_core_push_job (GumScriptCore * self,
                           GumScriptJobFunc job_func,
                           gpointer data,
                           GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy, self);
}

static void
gum_script_core_add_scheduled_callback (GumScriptCore * self,
                                        GumScheduledCallback * callback)
{
  self->scheduled_callbacks =
      g_slist_prepend (self->scheduled_callbacks, callback);
}

static void
gum_script_core_remove_scheduled_callback (GumScriptCore * self,
                                           GumScheduledCallback * callback)
{
  self->scheduled_callbacks =
      g_slist_remove (self->scheduled_callbacks, callback);
}

static void
gum_script_core_on_schedule_callback (const FunctionCallbackInfo<Value> & info,
                                      gboolean repeat)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  Local<Value> func_val = info[0];
  if (!func_val->IsFunction ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "first argument must be a function")));
    return;
  }

  Local<Value> delay_val = info[1];
  if (!delay_val->IsNumber ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "second argument must be a number specifying delay")));
    return;
  }
  int32_t delay = delay_val->ToInt32 ()->Value ();
  if (delay < 0)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "second argument must be a positive integer")));
    return;
  }

  gint id = g_atomic_int_add (&self->last_callback_id, 1) + 1;
  GSource * source;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new (delay);
  GumScheduledCallback * callback =
      gum_scheduled_callback_new (id, repeat, source, self);
  callback->func = new GumPersistent<Function>::type (isolate,
      func_val.As <Function> ());
  callback->receiver = new GumPersistent<Value>::type (isolate, info.This ());
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      reinterpret_cast<GDestroyNotify> (gum_scheduled_callback_free));
  gum_script_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_v8_context (self->scheduler));

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
gum_script_core_on_set_timeout (const FunctionCallbackInfo<Value> & info)
{
  gum_script_core_on_schedule_callback (info, FALSE);
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
gum_script_core_on_set_interval (const FunctionCallbackInfo<Value> & info)
{
  gum_script_core_on_schedule_callback (info, TRUE);
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
gum_script_core_on_clear_timeout (const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
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
  gint id = id_val->ToInt32 ()->Value ();

  GumScheduledCallback * callback = NULL;
  for (cur = self->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumScheduledCallback * cb =
        static_cast<GumScheduledCallback *> (cur->data);
    if (cb->id == id)
    {
      callback = cb;
      self->scheduled_callbacks =
          g_slist_delete_link (self->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
    g_source_destroy (callback->source);

  info.GetReturnValue ().Set (callback != NULL);
}

static GumScheduledCallback *
gum_scheduled_callback_new (gint id,
                            gboolean repeat,
                            GSource * source,
                            GumScriptCore * core)
{
  GumScheduledCallback * callback;

  callback = g_slice_new (GumScheduledCallback);
  callback->id = id;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_scheduled_callback_free (GumScheduledCallback * callback)
{
  ScriptScope (callback->core->script);
  delete callback->func;
  delete callback->receiver;

  g_slice_free (GumScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumScheduledCallback * self =
      static_cast<GumScheduledCallback *> (user_data);
  Isolate * isolate = self->core->isolate;

  ScriptScope scope (self->core->script);
  Local<Function> func (Local<Function>::New (isolate, *self->func));
  Local<Value> receiver (Local<Value>::New (isolate, *self->receiver));
  func->Call (receiver, 0, NULL);

  if (!self->repeat)
    gum_script_core_remove_scheduled_callback (self->core, self);

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
gum_script_core_on_send (const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  String::Utf8Value message (info[0]);

  const guint8 * data = NULL;
  gint data_length = 0;
  if (!info[1]->IsNull ())
  {
    Local<Object> array = info[1]->ToObject ();
    if (array->HasIndexedPropertiesInExternalArrayData () &&
        array->GetIndexedPropertiesExternalArrayDataType ()
        == kExternalUint8Array)
    {
      data = static_cast<guint8 *> (
          array->GetIndexedPropertiesExternalArrayData ());
      data_length = array->GetIndexedPropertiesExternalArrayDataLength ();
    }
    else
    {
      isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
          isolate, "unsupported data value")));
      return;
    }
  }

  _gum_script_core_emit_message (self, *message, data, data_length);
}

/*
 * Prototype:
 * _setIncomingMessageCallback(callback)
 *
 * Docs:
 * [PRIVATE] Set callback to fire when a message is recieved
 *
 * Example:
 * TBW
 */
static void
gum_script_core_on_set_incoming_message_callback (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  if (info.Length () > 1)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "invalid argument count")));
    return;
  }

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (info.Length () == 1)
  {
    self->incoming_message_sink =
        gum_message_sink_new (info[0].As<Function> (), info.This (), isolate);
  }
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
gum_script_core_on_wait_for_event (const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());

  self->isolate->Exit ();
  {
    Unlocker ul (self->isolate);

    GUM_SCRIPT_CORE_LOCK ();
    guint start_count = self->event_count;
    while (self->event_count == start_count)
      g_cond_wait (&self->event_cond, &self->mutex);
    GUM_SCRIPT_CORE_UNLOCK ();
  }
  self->isolate->Enter ();
}

static void
gum_script_core_on_new_native_pointer (
    const FunctionCallbackInfo<Value> & info)
{
  Isolate * isolate = info.GetIsolate ();
  guint64 ptr;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new NativePointer()` to create a new instance,"
        " or use one of the two shorthands: `ptr()` and `NULL`")));
    return;
  }

  if (info.Length () == 0)
  {
    ptr = 0;
  }
  else
  {
    String::Utf8Value ptr_as_utf8 (info[0]);
    const gchar * ptr_as_string = *ptr_as_utf8;
    gchar * endptr;
    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
      if (endptr == ptr_as_string + 2)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "NativePointer: argument is not a valid "
            "hexadecimal string")));
        return;
      }
    }
    else
    {
      ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
      if (endptr == ptr_as_string)
      {
        isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
            isolate, "NativePointer: argument is not a valid "
            "decimal string")));
        return;
      }
    }
  }

  info.Holder ()->SetInternalField (0,
      External::New (info.GetIsolate (), GSIZE_TO_POINTER (ptr)));
}

/*
 * Prototype:
 * NativePointer.isNull(pointer)
 *
 * Docs:
 * Returns true if a pointer is null, otherwise false
 *
 * Example:
 * TBW
 */
static void
gum_script_core_on_native_pointer_is_null (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (GUM_NATIVE_POINTER_VALUE (info.Holder ()) == 0);
}

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
    static void \
    gum_script_core_on_native_pointer_ ## name ( \
        const FunctionCallbackInfo<Value> & info) \
    { \
        GumScriptCore * self = static_cast<GumScriptCore *> ( \
            info.Data ().As<External> ()->Value ()); \
        \
        guint64 lhs = reinterpret_cast<guint64> ( \
            GUM_NATIVE_POINTER_VALUE (info.Holder ())); \
        \
        guint64 rhs; \
        Local<FunctionTemplate> native_pointer ( \
            Local<FunctionTemplate>::New (self->isolate, \
                *self->native_pointer)); \
        if (native_pointer->HasInstance (info[0])) \
        { \
          rhs = reinterpret_cast<guint64> ( \
              GUM_NATIVE_POINTER_VALUE (info[0].As<Object> ())); \
        } \
        else \
        { \
          rhs = info[0]->ToInteger ()->Value (); \
        } \
        gpointer result = GSIZE_TO_POINTER (lhs op rhs); \
        \
        info.GetReturnValue ().Set (_gum_script_pointer_new (result, self)); \
    }

GUM_DEFINE_NATIVE_POINTER_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (xor, ^)

/*
 * Prototype:
 * NativePointer.toInt32(pointer)
 *
 * Docs:
 * Represents the pointer as a signed 32-bit integer
 *
 * Example:
 * TBW
 */
static void
gum_script_core_on_native_pointer_to_int32 (
    const FunctionCallbackInfo<Value> & info)
{
  info.GetReturnValue ().Set (static_cast<int32_t> (GPOINTER_TO_SIZE (
      GUM_NATIVE_POINTER_VALUE (info.Holder ()))));
}

/*
 * Prototype:
 * NativePointer.toString(pointer[, radix=16])
 *
 * Docs:
 * Represents the pointer as a either a base-10 or base-16 output.
 *
 * Example:
 * TBW
 */
static void
gum_script_core_on_native_pointer_to_string (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gsize ptr = GPOINTER_TO_SIZE (GUM_NATIVE_POINTER_VALUE (info.Holder ()));
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

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, buf));
}

/*
 * Prototype:
 * NativePointer.toJSON(pointer)
 *
 * Docs:
 * Represents the pointer as a JSON-formatted object
 *
 * Example:
 * TBW
 */
static void
gum_script_core_on_native_pointer_to_json (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;

  gsize ptr = GPOINTER_TO_SIZE (GUM_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar buf[32];
  sprintf (buf, "0x%" G_GSIZE_MODIFIER "x", ptr);

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, buf));
}

static void
gum_script_core_on_new_native_function (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
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

  if (!_gum_script_pointer_get (info[0], &func->fn, self))
    goto error;

  rtype_value = info[1];
  if (!rtype_value->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeFunction: second argument must be a string specifying "
        "return type")));
    goto error;
  }
  if (!gum_script_ffi_type_get (self, rtype_value, &rtype))
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
    else if (!gum_script_ffi_type_get (self, type,
        &func->atypes[is_variadic ? i - 1 : i]))
    {
      goto error;
    }
  }
  if (is_variadic)
    nargs_total--;

  abi = FFI_DEFAULT_ABI;
  if (info.Length () > 3)
  {
    if (!gum_script_ffi_abi_get (self, info[3], &abi))
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

  instance = info.Holder ();
  instance->SetInternalField (0, External::New (isolate, func->fn));
  instance->SetAlignedPointerInInternalField (1, func);

  func->weak_instance = new GumPersistent<Object>::type (isolate, instance);
  func->weak_instance->SetWeak (func, gum_ffi_function_on_weak_notify);
  func->weak_instance->MarkIndependent ();

  g_hash_table_insert (self->native_functions, func, func);

  return;

error:
  gum_ffi_function_free (func);

  return;
}

static void
gum_ffi_function_on_weak_notify (
    const WeakCallbackData<Object, GumFFIFunction> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumFFIFunction * self = data.GetParameter ();
  g_hash_table_remove (self->core->native_functions, self);
}

static void
gum_script_core_on_invoke_native_function (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->isolate;
  Local<Object> instance = info.Holder ();
  GumFFIFunction * func = static_cast<GumFFIFunction *> (
      instance->GetAlignedPointerFromInternalField (1));

  if (info.Length () != static_cast<gint> (func->cif.nargs))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeFunction: bad argument count")));
    return;
  }

  GumFFIValue rvalue;
  void ** avalue = static_cast<void **> (
      g_alloca (func->cif.nargs * sizeof (void *)));
  GumFFIValue * ffi_args = static_cast<GumFFIValue *> (
      g_alloca (func->cif.nargs * sizeof (GumFFIValue)));
  for (uint32_t i = 0; i != func->cif.nargs; i++)
  {
    if (!gum_script_value_to_ffi_type (self, info[i], &ffi_args[i],
        func->cif.arg_types[i]))
    {
      return;
    }
    avalue[i] = &ffi_args[i];
  }

  ffi_call (&func->cif, FFI_FN (func->fn), &rvalue, avalue);

  Local<Value> result;
  if (!gum_script_value_from_ffi_type (self, &result, &rvalue, func->cif.rtype))
    return;

  info.GetReturnValue ().Set (result);
}

static void
gum_ffi_function_free (GumFFIFunction * func)
{
  delete func->weak_instance;
  g_free (func->atypes);
  g_slice_free (GumFFIFunction, func);
}

static void
gum_script_core_on_new_native_callback (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
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
  callback->receiver = new GumPersistent<Value>::type (isolate, info.This ());

  rtype_value = info[1];
  if (!rtype_value->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: second argument must be a string specifying "
        "return type")));
    goto error;
  }
  if (!gum_script_ffi_type_get (self, rtype_value, &rtype))
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
    if (!gum_script_ffi_type_get (self, atypes_array->Get (i),
        &callback->atypes[i]))
    {
      goto error;
    }
  }

  abi = FFI_DEFAULT_ABI;
  if (info.Length () > 3)
  {
    if (!gum_script_ffi_abi_get (self, info[3], &abi))
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
        gum_script_core_on_invoke_native_callback, callback, func) != FFI_OK)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "NativeCallback: failed to prepare closure")));
    goto error;
  }

  instance = info.Holder ();
  instance->SetInternalField (0, External::New (isolate, func));

  callback->weak_instance = new GumPersistent<Object>::type (isolate, instance);
  callback->weak_instance->SetWeak (callback,
      gum_script_core_on_free_native_callback);
  callback->weak_instance->MarkIndependent ();

  g_hash_table_insert (self->native_callbacks, callback, callback);

  return;

error:
  gum_ffi_callback_free (callback);
  return;
}

static void
gum_script_core_on_free_native_callback (
    const WeakCallbackData<Object, GumFFICallback> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumFFICallback * self = data.GetParameter ();
  g_hash_table_remove (self->core->native_callbacks, self);
}

static void
gum_script_core_on_invoke_native_callback (ffi_cif * cif,
                                           void * return_value,
                                           void ** args,
                                           void * user_data)
{
  GumFFICallback * self = static_cast<GumFFICallback *> (user_data);
  ScriptScope scope (self->core->script);
  Isolate * isolate = self->core->isolate;
  GumFFIValue * retval = static_cast<GumFFIValue *> (return_value);

  Local<Value> * argv = static_cast<Local<Value> *> (
      g_alloca (cif->nargs * sizeof (Local<Value>)));
  for (guint i = 0; i != cif->nargs; i++)
  {
    if (!gum_script_value_from_ffi_type (self->core, &argv[i],
          static_cast<GumFFIValue *> (args[i]), cif->arg_types[i]))
    {
      if (cif->rtype != &ffi_type_void)
        retval->v_pointer = NULL;
      return;
    }
  }

  Local<Function> func (Local<Function>::New (isolate, *self->func));
  Local<Value> receiver (Local<Value>::New (isolate, *self->receiver));
  Local<Value> result = func->Call (receiver, cif->nargs, argv);
  if (cif->rtype != &ffi_type_void)
  {
    if (!scope.HasPendingException ())
      gum_script_value_to_ffi_type (self->core, result, retval, cif->rtype);
    else
      retval->v_pointer = NULL;
  }
}

static void
gum_ffi_callback_free (GumFFICallback * callback)
{
  delete callback->weak_instance;

  delete callback->func;
  delete callback->receiver;

  ffi_closure_free (callback->closure);
  g_free (callback->atypes);

  g_slice_free (GumFFICallback, callback);
}

static void
gum_script_core_on_new_cpu_context (
    const FunctionCallbackInfo<Value> & info)
{
  GumScriptCore * self = static_cast<GumScriptCore *> (
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
gum_script_core_on_cpu_context_get_register (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  Local<Object> instance = info.Holder ();
  GumScriptCore * self = static_cast<GumScriptCore *> (
      instance->GetAlignedPointerFromInternalField (2));
  gpointer * cpu_context = static_cast<gpointer *> (
      instance->GetInternalField (0).As<External> ()->Value ());
  gsize offset = info.Data ().As<Integer> ()->Value ();

  (void) property;

  info.GetReturnValue ().Set (
      _gum_script_pointer_new (cpu_context[offset], self));
}

static void
gum_script_core_on_cpu_context_set_register (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  Isolate * isolate = info.GetIsolate ();
  Local<Object> instance = info.Holder ();
  GumScriptCore * self = static_cast<GumScriptCore *> (
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
        GUM_NATIVE_POINTER_VALUE (value.As<Object> ()));
  }
  else
  {
    raw_value = value->ToInteger ()->Value ();
  }

  cpu_context[offset] = raw_value;
}

static GumMessageSink *
gum_message_sink_new (Handle<Function> callback,
                      Handle<Value> receiver,
                      Isolate * isolate)
{
  GumMessageSink * sink;

  sink = g_slice_new (GumMessageSink);
  sink->callback = new GumPersistent<Function>::type (isolate, callback);
  sink->receiver = new GumPersistent<Value>::type (isolate, receiver);
  sink->isolate = isolate;

  return sink;
}

static void
gum_message_sink_free (GumMessageSink * sink)
{
  if (sink == NULL)
    return;

  delete sink->callback;
  delete sink->receiver;

  g_slice_free (GumMessageSink, sink);
}

static void
gum_message_sink_handle_message (GumMessageSink * self,
                                 const gchar * message)
{
  Isolate * isolate = self->isolate;
  Handle<Value> argv[] = { String::NewFromUtf8 (isolate, message) };

  Local<Function> callback (Local<Function>::New (isolate, *self->callback));
  Local<Value> receiver (Local<Value>::New (isolate, *self->receiver));
  callback->Call (receiver, 1, argv);
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
gum_script_ffi_type_get (GumScriptCore * core,
                         Handle<Value> name,
                         ffi_type ** type)
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

  core->isolate->ThrowException (Exception::TypeError (
      String::NewFromUtf8 (core->isolate, "invalid type specified")));
  return FALSE;
}

static gboolean
gum_script_ffi_abi_get (GumScriptCore * core,
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
gum_script_value_to_ffi_type (GumScriptCore * core,
                              const Handle<Value> svalue,
                              GumFFIValue * value,
                              const ffi_type * type)
{
  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gum_script_pointer_get (svalue, &value->v_pointer, core))
      return FALSE;
  }
  else if (type == &ffi_type_sint)
  {
    value->v_sint = svalue->IntegerValue ();
  }
  else if (type == &ffi_type_uint)
  {
    value->v_uint = static_cast<guint> (svalue->IntegerValue ());
  }
  else if (type == &ffi_type_slong)
  {
    value->v_slong = svalue->IntegerValue ();
  }
  else if (type == &ffi_type_ulong)
  {
    value->v_ulong = static_cast<gulong> (svalue->IntegerValue ());
  }
  else if (type == &ffi_type_schar)
  {
    value->v_schar = static_cast<gchar> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uchar)
  {
    value->v_uchar = static_cast<guchar> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_float)
  {
    value->v_float = svalue->NumberValue ();
  }
  else if (type == &ffi_type_double)
  {
    value->v_double = svalue->NumberValue ();
  }
  else if (type == &ffi_type_sint8)
  {
    value->v_sint8 = static_cast<gint8> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint8)
  {
    value->v_uint8 = static_cast<guint8> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_sint16)
  {
    value->v_sint16 = static_cast<gint16> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint16)
  {
    value->v_uint16 = static_cast<guint16> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_sint32)
  {
    value->v_sint32 = static_cast<gint32> (svalue->Int32Value ());
  }
  else if (type == &ffi_type_uint32)
  {
    value->v_uint32 = static_cast<guint32> (svalue->Uint32Value ());
  }
  else if (type == &ffi_type_sint64)
  {
    value->v_sint64 = static_cast<gint64> (svalue->IntegerValue ());
  }
  else if (type == &ffi_type_uint64)
  {
    value->v_uint64 = static_cast<guint64> (svalue->IntegerValue ());
  }
  else
  {
    core->isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        core->isolate, "value_to_ffi_type: unsupported type")));
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_script_value_from_ffi_type (GumScriptCore * core,
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
    *svalue = _gum_script_pointer_new (value->v_pointer, core);
  }
  else if (type == &ffi_type_sint)
  {
    *svalue = Number::New (isolate, value->v_sint);
  }
  else if (type == &ffi_type_uint)
  {
    *svalue = Number::New (isolate, value->v_uint);
  }
  else if (type == &ffi_type_slong)
  {
    *svalue = Number::New (isolate, value->v_slong);
  }
  else if (type == &ffi_type_ulong)
  {
    *svalue = Number::New (isolate, value->v_ulong);
  }
  else if (type == &ffi_type_schar)
  {
    *svalue = Integer::New (isolate, value->v_schar);
  }
  else if (type == &ffi_type_uchar)
  {
    *svalue = Integer::NewFromUnsigned (isolate, value->v_uchar);
  }
  else if (type == &ffi_type_float)
  {
    *svalue = Number::New (isolate, value->v_float);
  }
  else if (type == &ffi_type_double)
  {
    *svalue = Number::New (isolate, value->v_double);
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
    *svalue = Number::New (isolate, value->v_sint64);
  }
  else if (type == &ffi_type_uint64)
  {
    *svalue = Number::New (isolate, value->v_uint64);
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "value_from_ffi_type: unsupported type")));
    return FALSE;
  }

  return TRUE;
}

GumByteArray *
_gum_byte_array_new (gpointer data,
                     gsize size,
                     GumScriptCore * core)
{
  Isolate * isolate = core->isolate;
  GumByteArray * buffer;

  Local<Object> arr (Object::New (isolate));
  arr->ForceSet (String::NewFromUtf8 (isolate, "length"),
      Int32::New (isolate, size),
      static_cast<PropertyAttribute> (ReadOnly | DontDelete));
  if (size > 0)
  {
    arr->SetIndexedPropertiesToExternalArrayData (data,
        kExternalUnsignedByteArray, size);
  }
  buffer = g_slice_new (GumByteArray);
  buffer->instance = new GumPersistent<Object>::type (core->isolate, arr);
  buffer->instance->MarkIndependent ();
  buffer->instance->SetWeak (buffer, gum_byte_array_on_weak_notify);
  buffer->data = data;
  buffer->size = size;
  buffer->core = core;

  if (buffer->size > 0)
  {
    core->isolate->AdjustAmountOfExternalAllocatedMemory (size);
  }

  g_hash_table_insert (core->byte_arrays, buffer, buffer);

  return buffer;
}

void
_gum_byte_array_free (GumByteArray * buffer)
{
  if (buffer->size > 0)
  {
    buffer->core->isolate->AdjustAmountOfExternalAllocatedMemory (
        -static_cast<gssize> (buffer->size));
  }

  delete buffer->instance;
  g_free (buffer->data);
  g_slice_free (GumByteArray, buffer);
}

static void
gum_byte_array_on_weak_notify (
    const WeakCallbackData<Object, GumByteArray> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumByteArray * self = data.GetParameter ();
  g_hash_table_remove (self->core->byte_arrays, self);
}

GumHeapBlock *
_gum_heap_block_new (gpointer data,
                     gsize size,
                     GumScriptCore * core)
{
  GumHeapBlock * block;

  block = g_slice_new (GumHeapBlock);
  block->instance = new GumPersistent<Object>::type (core->isolate,
      _gum_script_pointer_new (data, core));
  block->instance->MarkIndependent ();
  block->instance->SetWeak (block, gum_heap_block_on_weak_notify);
  block->data = data;
  block->size = size;
  block->core = core;

  core->isolate->AdjustAmountOfExternalAllocatedMemory (size);

  g_hash_table_insert (core->heap_blocks, block, block);

  return block;
}

void
_gum_heap_block_free (GumHeapBlock * block)
{
  block->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -static_cast<gssize> (block->size));

  delete block->instance;
  g_free (block->data);
  g_slice_free (GumHeapBlock, block);
}

static void
gum_heap_block_on_weak_notify (
    const WeakCallbackData<Object, GumHeapBlock> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumHeapBlock * self = data.GetParameter ();
  g_hash_table_remove (self->core->heap_blocks, self);
}

Local<Object>
_gum_script_pointer_new (gpointer address,
                         GumScriptCore * core)
{
  Local<Object> native_pointer_value (Local<Object>::New (core->isolate,
      *core->native_pointer_value));
  Local<Object> native_pointer_object (native_pointer_value->Clone ());
  native_pointer_object->SetInternalField (0,
      External::New (core->isolate, address));
  return native_pointer_object;
}

gboolean
_gum_script_pointer_get (Handle<Value> value,
                         gpointer * target,
                         GumScriptCore * core)
{
  Isolate * isolate = core->isolate;

  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (
      isolate, *core->native_pointer));
  if (!native_pointer->HasInstance (value))
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "expected NativePointer object")));
    return FALSE;
  }
  *target = GUM_NATIVE_POINTER_VALUE (value.As<Object> ());

  return TRUE;
}

v8::Local<v8::Object>
_gum_script_cpu_context_new (const GumCpuContext * cpu_context,
                             GumScriptCore * core)
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
_gum_script_cpu_context_new (GumCpuContext * cpu_context,
                             GumScriptCore * core)
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

gboolean
_gum_script_cpu_context_get (v8::Handle<v8::Value> value,
                             GumCpuContext ** target,
                             GumScriptCore * core)
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
  *target = GUM_CPU_CONTEXT_VALUE (value.As<Object> ());

  return TRUE;
}

gboolean
_gum_script_set (Handle<Object> object,
                 const gchar * key,
                 Handle<Value> value,
                 GumScriptCore * core)
{
  Isolate * isolate = core->isolate;
  Maybe<bool> success = object->ForceSet (isolate->GetCurrentContext (),
      String::NewFromOneByte (isolate,
          reinterpret_cast<const uint8_t *> (key)),
      value,
      static_cast<PropertyAttribute> (ReadOnly | DontDelete));
  return success.IsJust ();
}

gboolean
_gum_script_set_uint (Handle<Object> object,
                      const gchar * key,
                      guint value,
                      GumScriptCore * core)
{
  return _gum_script_set (object,
      key,
      Integer::NewFromUnsigned (core->isolate, value),
      core);
}

gboolean
_gum_script_set_pointer (Handle<Object> object,
                         const gchar * key,
                         gpointer value,
                         GumScriptCore * core)
{
  return _gum_script_set (object,
      key,
      _gum_script_pointer_new (value, core),
      core);
}

gboolean
_gum_script_set_pointer (Handle<Object> object,
                         const gchar * key,
                         GumAddress value,
                         GumScriptCore * core)
{
  return _gum_script_set (object,
      key,
      _gum_script_pointer_new (GSIZE_TO_POINTER (value), core),
      core);
}

gboolean
_gum_script_set_ascii (Handle<Object> object,
                       const gchar * key,
                       const gchar * value,
                       GumScriptCore * core)
{
  return _gum_script_set (object,
      key,
      String::NewFromOneByte (core->isolate,
          reinterpret_cast<const uint8_t *> (value)),
      core);
}

gboolean
_gum_script_set_utf8 (Handle<Object> object,
                      const gchar * key,
                      const gchar * value,
                      GumScriptCore * core)
{
  return _gum_script_set (object,
      key,
      String::NewFromUtf8 (core->isolate, value),
      core);
}

gboolean
_gum_script_callbacks_get (Handle<Object> callbacks,
                           const gchar * name,
                           Handle<Function> * callback_function,
                           GumScriptCore * core)
{
  if (!_gum_script_callbacks_get_opt (callbacks, name, callback_function, core))
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
_gum_script_callbacks_get_opt (Handle<Object> callbacks,
                               const gchar * name,
                               Handle<Function> * callback_function,
                               GumScriptCore * core)
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
_gum_script_page_protection_get (Handle<Value> prot_val,
                                 GumPageProtection * prot,
                                 GumScriptCore * core)
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
