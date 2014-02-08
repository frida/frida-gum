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

#include "gumscriptcore.h"

#include "gumscriptscope.h"

#include <ffi.h>
#include <string.h>

using namespace v8;

typedef struct _GumFFIFunction GumFFIFunction;
typedef struct _GumFFICallback GumFFICallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumScheduledCallback
{
  gint id;
  gboolean repeat;
  Persistent<Function> func;
  Persistent<Object> receiver;
  GSource * source;
  GumScriptCore * core;
};

struct _GumMessageSink
{
  Persistent<Function> callback;
  Persistent<Object> receiver;
};

struct _GumFFIFunction
{
  gpointer fn;
  ffi_cif cif;
  ffi_type ** atypes;
};

struct _GumFFICallback
{
  GumScriptCore * core;
  Persistent<Function> func;
  Persistent<Object> receiver;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
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

static Handle<Value> gum_script_core_on_console_log (const Arguments & args);
static Handle<Value> gum_script_core_on_set_timeout (const Arguments & args);
static Handle<Value> gum_script_core_on_set_interval (const Arguments & args);
static Handle<Value> gum_script_core_on_clear_timeout (const Arguments & args);
static GumScheduledCallback * gum_scheduled_callback_new (gint id,
    gboolean repeat, GSource * source, GumScriptCore * core);
static void gum_scheduled_callback_free (GumScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);
static Handle<Value> gum_script_core_on_send (const Arguments & args);
static Handle<Value> gum_script_core_on_set_incoming_message_callback (
    const Arguments & args);
static Handle<Value> gum_script_core_on_wait_for_event (
    const Arguments & args);

static Handle<Value> gum_script_core_on_new_native_pointer (
    const Arguments & args);
static Handle<Value> gum_script_core_on_native_pointer_add (
    const Arguments & args);
static Handle<Value> gum_script_core_on_native_pointer_sub (
    const Arguments & args);
static Handle<Value> gum_script_core_on_native_pointer_to_int32 (
    const Arguments & args);
static Handle<Value> gum_script_core_on_native_pointer_to_string (
    const Arguments & args);
static Handle<Value> gum_script_core_on_native_pointer_to_json (
    const Arguments & args);

static Handle<Value> gum_script_core_on_new_native_function (
    const Arguments & args);
static void gum_script_core_on_free_native_function (Persistent<Value> object,
    void * data);
static Handle<Value> gum_script_core_on_invoke_native_function (
    const Arguments & args);
static void gum_ffi_function_free (GumFFIFunction * func);

static Handle<Value> gum_script_core_on_new_native_callback (
    const Arguments & args);
static void gum_script_core_on_free_native_callback (Persistent<Value> object,
    void * data);
static void gum_script_core_on_invoke_native_callback (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);
static void gum_ffi_callback_free (GumFFICallback * callback);

static GumMessageSink * gum_message_sink_new (Handle<Function> callback,
    Handle<Object> receiver);
static void gum_message_sink_free (GumMessageSink * sink);
static void gum_message_sink_handle_message (GumMessageSink * self,
    const gchar * message);

static gboolean gum_script_ffi_type_get (Handle<Value> name, ffi_type ** type);
static gboolean gum_script_ffi_abi_get (Handle<Value> name, ffi_abi * abi);
static gboolean gum_script_value_to_ffi_type (GumScriptCore * self,
    const Handle<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_script_value_from_ffi_type (GumScriptCore * self,
    Handle<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

void
_gum_script_core_init (GumScriptCore * self,
                       GumScript * script,
                       GMainContext * main_context,
                       v8::Isolate * isolate,
                       Handle<ObjectTemplate> scope)
{
  self->script = script;
  self->main_context = main_context;
  self->isolate = isolate;

  self->mutex = g_mutex_new ();
  self->event_cond = g_cond_new ();

  Handle<ObjectTemplate> console = ObjectTemplate::New ();
  console->Set (String::New ("log"), FunctionTemplate::New (
      gum_script_core_on_console_log, External::Wrap (self)));
  scope->Set (String::New ("console"), console);

  scope->Set (String::New ("setTimeout"),
      FunctionTemplate::New (gum_script_core_on_set_timeout, External::Wrap (self)));
  scope->Set (String::New ("setInterval"),
      FunctionTemplate::New (gum_script_core_on_set_interval,
          External::Wrap (self)));
  scope->Set (String::New ("clearTimeout"),
      FunctionTemplate::New (gum_script_core_on_clear_timeout,
          External::Wrap (self)));
  scope->Set (String::New ("clearInterval"),
      FunctionTemplate::New (gum_script_core_on_clear_timeout,
          External::Wrap (self)));
  scope->Set (String::New ("_send"),
      FunctionTemplate::New (gum_script_core_on_send, External::Wrap (self)));
  scope->Set (String::New ("_setIncomingMessageCallback"),
      FunctionTemplate::New (gum_script_core_on_set_incoming_message_callback,
          External::Wrap (self)));
  scope->Set (String::New ("_waitForEvent"),
      FunctionTemplate::New (gum_script_core_on_wait_for_event,
          External::Wrap (self)));

  Local<FunctionTemplate> native_pointer = FunctionTemplate::New (
      gum_script_core_on_new_native_pointer);
  native_pointer->SetClassName (String::New ("NativePointer"));
  Local<ObjectTemplate> native_pointer_proto =
      native_pointer->PrototypeTemplate ();
  native_pointer_proto->Set (String::New ("add"),
      FunctionTemplate::New (gum_script_core_on_native_pointer_add,
      External::Wrap (self)));
  native_pointer_proto->Set (String::New ("sub"),
      FunctionTemplate::New (gum_script_core_on_native_pointer_sub,
      External::Wrap (self)));
  native_pointer_proto->Set (String::New ("toInt32"),
      FunctionTemplate::New (gum_script_core_on_native_pointer_to_int32));
  native_pointer_proto->Set (String::New ("toString"),
      FunctionTemplate::New (gum_script_core_on_native_pointer_to_string));
  native_pointer_proto->Set (String::New ("toJSON"),
      FunctionTemplate::New (gum_script_core_on_native_pointer_to_json));
  native_pointer->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::New ("NativePointer"), native_pointer);
  self->native_pointer = Persistent<FunctionTemplate>::New (native_pointer);

  Local<FunctionTemplate> native_function = FunctionTemplate::New (
      gum_script_core_on_new_native_function, External::Wrap (self));
  native_function->SetClassName (String::New ("NativeFunction"));
  native_function->Inherit (native_pointer);
  Local<ObjectTemplate> native_function_object =
      native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gum_script_core_on_invoke_native_function, External::Wrap (self));
  native_function_object->SetInternalFieldCount (2);
  scope->Set (String::New ("NativeFunction"), native_function);

  Local<FunctionTemplate> native_callback = FunctionTemplate::New (
      gum_script_core_on_new_native_callback, External::Wrap (self));
  native_callback->SetClassName (String::New ("NativeCallback"));
  native_callback->Inherit (native_pointer);
  native_callback->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::New ("NativeCallback"), native_callback);
}

void
_gum_script_core_realize (GumScriptCore * self)
{
  self->native_pointer_value = Persistent<Object>::New (
      self->native_pointer->InstanceTemplate ()->NewInstance ());
}

void
_gum_script_core_dispose (GumScriptCore * self)
{
  while (self->scheduled_callbacks != NULL)
  {
    g_source_destroy (static_cast<GumScheduledCallback *> (
        self->scheduled_callbacks->data)->source);
    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);
  }

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (self->message_handler_notify != NULL)
    self->message_handler_notify (self->message_handler_data);

  self->native_pointer_value.Dispose ();
  self->native_pointer_value.Clear ();
}

void
_gum_script_core_finalize (GumScriptCore * self)
{
  self->native_pointer.Dispose ();
  self->native_pointer.Clear ();

  g_mutex_free (self->mutex);
  g_cond_free (self->event_cond);
}

void
_gum_script_core_set_message_handler (GumScriptCore * self,
                                      GumScriptMessageHandler func,
                                      gpointer data,
                                      GDestroyNotify notify)
{
  self->message_handler_func = func;
  self->message_handler_data = data;
  self->message_handler_notify = notify;
}

void
_gum_script_core_emit_message (GumScriptCore * self,
                               const gchar * message,
                               const guint8 * data,
                               gint data_length)
{
  if (self->message_handler_func != NULL)
  {
    self->message_handler_func (self->script, message, data, data_length,
        self->message_handler_data);
  }
}

void
_gum_script_core_post_message (GumScriptCore * self,
                               const gchar * message)
{
  if (self->incoming_message_sink != NULL)
  {
    {
      ScriptScope scope (self->script);
      gum_message_sink_handle_message (self->incoming_message_sink, message);
      self->event_count++;
    }

    g_mutex_lock (self->mutex);
    g_cond_broadcast (self->event_cond);
    g_mutex_unlock (self->mutex);
  }
}

static Handle<Value>
gum_script_core_on_console_log (const Arguments & args)
{
  String::Utf8Value message (args[0]);
  g_print ("%s\n", *message);

  return Undefined ();
}

static void
gum_script_core_add_scheduled_callback (GumScriptCore * self,
                                        GumScheduledCallback * callback)
{
  g_mutex_lock (self->mutex);
  self->scheduled_callbacks =
      g_slist_prepend (self->scheduled_callbacks, callback);
  g_mutex_unlock (self->mutex);
}

static void
gum_script_core_remove_scheduled_callback (GumScriptCore * self,
                                           GumScheduledCallback * callback)
{
  g_mutex_lock (self->mutex);
  self->scheduled_callbacks =
      g_slist_remove (self->scheduled_callbacks, callback);
  g_mutex_unlock (self->mutex);
}

static Handle<Value>
gum_script_core_on_schedule_callback (const Arguments & args,
                                      gboolean repeat)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));

  Local<Value> func_val = args[0];
  if (!func_val->IsFunction ())
  {
    ThrowException (Exception::TypeError (String::New (
        "first argument must be a function")));
    return Undefined ();
  }

  Local<Value> delay_val = args[1];
  if (!delay_val->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New (
        "second argument must be a number specifying delay")));
    return Undefined ();
  }
  int32_t delay = delay_val->ToInt32 ()->Value ();
  if (delay < 0)
  {
    ThrowException (Exception::TypeError (String::New (
        "second argument must be a positive integer")));
    return Undefined ();
  }

  gint id = g_atomic_int_exchange_and_add (&self->last_callback_id, 1) + 1;
  GSource * source;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new (delay);
  GumScheduledCallback * callback =
      gum_scheduled_callback_new (id, repeat, source, self);
  callback->func = Persistent<Function>::New (Local<Function>::Cast (func_val));
  callback->receiver = Persistent<Object>::New (args.This ());
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      reinterpret_cast<GDestroyNotify> (gum_scheduled_callback_free));
  gum_script_core_add_scheduled_callback (self, callback);

  g_source_attach (source, self->main_context);

  return Int32::New (id);
}

static Handle<Value>
gum_script_core_on_set_timeout (const Arguments & args)
{
  return gum_script_core_on_schedule_callback (args, FALSE);
}

static Handle<Value>
gum_script_core_on_set_interval (const Arguments & args)
{
  return gum_script_core_on_schedule_callback (args, TRUE);
}

static Handle<Value>
gum_script_core_on_clear_timeout (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));
  GSList * cur;

  Local<Value> id_val = args[0];
  if (!id_val->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New (
        "argument must be a timeout id")));
    return Undefined ();
  }
  gint id = id_val->ToInt32 ()->Value ();

  GumScheduledCallback * callback = NULL;
  g_mutex_lock (self->mutex);
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
  g_mutex_unlock (self->mutex);

  if (callback != NULL)
    g_source_destroy (callback->source);

  return (callback != NULL) ? True () : False ();
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
  callback->func.Dispose ();
  callback->receiver.Dispose ();

  g_slice_free (GumScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumScheduledCallback * self =
      static_cast<GumScheduledCallback *> (user_data);

  ScriptScope scope (self->core->script);
  self->func->Call (self->receiver, 0, 0);

  if (!self->repeat)
    gum_script_core_remove_scheduled_callback (self->core, self);

  return self->repeat;
}

static Handle<Value>
gum_script_core_on_send (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));

  String::Utf8Value message (args[0]);

  const guint8 * data = NULL;
  gint data_length = 0;
  if (!args[1]->IsNull ())
  {
    Local<Object> array = args[1]->ToObject ();
    if (array->HasIndexedPropertiesInExternalArrayData () &&
        array->GetIndexedPropertiesExternalArrayDataType ()
        == kExternalUnsignedByteArray)
    {
      data = static_cast<guint8 *> (
          array->GetIndexedPropertiesExternalArrayData ());
      data_length = array->GetIndexedPropertiesExternalArrayDataLength ();
    }
    else
    {
      ThrowException (Exception::TypeError (String::New (
          "unsupported data value")));
      return Undefined ();
    }
  }

  _gum_script_core_emit_message (self, *message, data, data_length);

  return Undefined ();
}

static Handle<Value>
gum_script_core_on_set_incoming_message_callback (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));

  if (args.Length () > 1)
  {
    ThrowException (Exception::TypeError (String::New (
        "invalid argument count")));
    return Undefined ();
  }

  gum_message_sink_free (self->incoming_message_sink);
  self->incoming_message_sink = NULL;

  if (args.Length () == 1)
  {
    self->incoming_message_sink =
        gum_message_sink_new (Local<Function>::Cast (args[0]), args.This ());
  }

  return Undefined ();
}

static Handle<Value>
gum_script_core_on_wait_for_event (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));
  guint start_count;

  start_count = self->event_count;
  while (self->event_count == start_count)
  {
    self->isolate->Exit ();

    {
      Unlocker ul (self->isolate);

      g_mutex_lock (self->mutex);
      g_cond_wait (self->event_cond, self->mutex);
      g_mutex_unlock (self->mutex);
    }

    self->isolate->Enter ();
  }

  return Undefined ();
}

static Handle<Value>
gum_script_core_on_new_native_pointer (const Arguments & args)
{
  guint64 ptr;

  if (args.Length () == 0)
  {
    ptr = 0;
  }
  else
  {
    String::Utf8Value ptr_as_utf8 (args[0]);
    const gchar * ptr_as_string = *ptr_as_utf8;
    gchar * endptr;
    if (g_str_has_prefix (ptr_as_string, "0x")) 
    {
      ptr = g_ascii_strtoull (ptr_as_string + 2, &endptr, 16);
      if (endptr == ptr_as_string + 2)
      {
        ThrowException (Exception::TypeError (String::New ("NativePointer: "
            "argument is not a valid hexadecimal string")));
        return Undefined ();
      }
    }
    else
    {
      ptr = g_ascii_strtoull (ptr_as_string, &endptr, 10);
      if (endptr == ptr_as_string)
      {
        ThrowException (Exception::TypeError (String::New ("NativePointer: "
            "argument is not a valid decimal string")));
        return Undefined ();
      }
    }
  }

  args.Holder ()->SetPointerInInternalField (0, GSIZE_TO_POINTER (ptr));

  return Undefined ();
}

static Handle<Value>
gum_script_core_on_native_pointer_add (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));

  guint64 lhs = reinterpret_cast<guint64> (
      args.Holder ()->GetPointerFromInternalField (0));
  if (self->native_pointer->HasInstance (args[0]))
  {
    guint64 rhs = reinterpret_cast<guint64> (
        args[0]->ToObject ()->GetPointerFromInternalField (0));
    return _gum_script_pointer_new (self, GSIZE_TO_POINTER (lhs + rhs));
  }
  else
  {
    return _gum_script_pointer_new (self,
        GSIZE_TO_POINTER (lhs + args[0]->ToInteger ()->Value ()));
  }
}

static Handle<Value>
gum_script_core_on_native_pointer_sub (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));

  guint64 lhs = reinterpret_cast<guint64> (
      args.Holder ()->GetPointerFromInternalField (0));
  if (self->native_pointer->HasInstance (args[0]))
  {
    guint64 rhs = reinterpret_cast<guint64> (
        args[0]->ToObject ()->GetPointerFromInternalField (0));
    return _gum_script_pointer_new (self, GSIZE_TO_POINTER (lhs - rhs));
  }
  else
  {
    return _gum_script_pointer_new (self,
        GSIZE_TO_POINTER (lhs - args[0]->ToInteger ()->Value ()));
  }
}

static Handle<Value>
gum_script_core_on_native_pointer_to_int32 (const Arguments & args)
{
  return Integer::New (static_cast<int32_t>
      (GPOINTER_TO_SIZE (args.Holder ()->GetPointerFromInternalField (0))));
}

static Handle<Value>
gum_script_core_on_native_pointer_to_string (const Arguments & args)
{
  gsize ptr = GPOINTER_TO_SIZE (
      args.Holder ()->GetPointerFromInternalField (0));
  gint radix = 16;
  bool radix_specified = args.Length () > 0;
  if (radix_specified)
    radix = args[0]->Int32Value ();
  if (radix != 10 && radix != 16)
  {
    ThrowException (Exception::TypeError (String::New ("unsupported radix")));
    return Undefined ();
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

  return String::New (buf);
}

static Handle<Value>
gum_script_core_on_native_pointer_to_json (const Arguments & args)
{
  gsize ptr = GPOINTER_TO_SIZE (
      args.Holder ()->GetPointerFromInternalField (0));

  gchar buf[32];
  sprintf (buf, "0x%" G_GSIZE_MODIFIER "x", ptr);

  return String::New (buf);
}

static Handle<Value>
gum_script_core_on_new_native_function (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));
  GumFFIFunction * func;
  Local<Value> rtype_value;
  ffi_type * rtype;
  Local<Value> atypes_value;
  Local<Array> atypes_array;
  uint32_t nargs_fixed, nargs_total, i;
  gboolean is_variadic;
  ffi_abi abi;
  Local<Object> instance;
  Persistent<Object> persistent_instance;

  func = g_slice_new0 (GumFFIFunction);

  if (!_gum_script_pointer_get (self, args[0], &func->fn))
    goto error;

  rtype_value = args[1];
  if (!rtype_value->IsString ())
  {
    ThrowException (Exception::TypeError (String::New ("NativeFunction: "
        "second argument must be a string specifying return type")));
    goto error;
  }
  if (!gum_script_ffi_type_get (rtype_value, &rtype))
    goto error;

  atypes_value = args[2];
  if (!atypes_value->IsArray ())
  {
    ThrowException (Exception::TypeError (String::New ("NativeFunction: "
        "third argument must be an array specifying argument types")));
    goto error;
  }
  atypes_array = Array::Cast (*atypes_value);
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
        ThrowException (Exception::TypeError (String::New ("NativeFunction: "
            "only one variadic marker may be specified")));
        goto error;
      }

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gum_script_ffi_type_get (type,
        &func->atypes[is_variadic ? i - 1 : i]))
    {
      goto error;
    }
  }
  if (is_variadic)
    nargs_total--;

  abi = FFI_DEFAULT_ABI;
  if (args.Length () > 3)
  {
    if (!gum_script_ffi_abi_get (args[3], &abi))
      goto error;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      ThrowException (Exception::TypeError (String::New ("NativeFunction: "
          "failed to compile function call interface")));
      goto error;
    }
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      ThrowException (Exception::TypeError (String::New ("NativeFunction: "
          "failed to compile function call interface")));
      goto error;
    }
  }

  instance = args.Holder ();
  instance->SetPointerInInternalField (0, func->fn);
  instance->SetPointerInInternalField (1, func);

  persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (func, gum_script_core_on_free_native_function);
  persistent_instance.MarkIndependent ();

  return Undefined ();

error:
  gum_ffi_function_free (func);
  return Undefined ();
}

static void
gum_script_core_on_free_native_function (Persistent<Value> object,
                                         void * data)
{
  HandleScope handle_scope;
  gum_ffi_function_free (static_cast<GumFFIFunction *> (data));
  object.Dispose ();
}

static Handle<Value>
gum_script_core_on_invoke_native_function (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));
  Local<Object> instance = args.Holder ();
  GumFFIFunction * func = static_cast<GumFFIFunction *> (
      instance->GetPointerFromInternalField (1));

  if (args.Length () != static_cast<gint> (func->cif.nargs))
  {
    ThrowException (Exception::TypeError (String::New ("NativeFunction: "
        "bad argument count")));
    return Undefined ();
  }

  GumFFIValue rvalue;
  void ** avalue = static_cast<void **> (
      g_alloca (func->cif.nargs * sizeof (void *)));
  GumFFIValue * ffi_args = static_cast<GumFFIValue *> (
      g_alloca (func->cif.nargs * sizeof (GumFFIValue)));
  for (uint32_t i = 0; i != func->cif.nargs; i++)
  {
    if (!gum_script_value_to_ffi_type (self, args[i], &ffi_args[i],
        func->cif.arg_types[i]))
    {
      return Undefined ();
    }
    avalue[i] = &ffi_args[i];
  }

  ffi_call (&func->cif, FFI_FN (func->fn), &rvalue, avalue);

  Local<Value> result;
  if (!gum_script_value_from_ffi_type (self, &result, &rvalue, func->cif.rtype))
  {
    return Undefined ();
  }

  return result;
}

static void
gum_ffi_function_free (GumFFIFunction * func)
{
  g_free (func->atypes);
  g_slice_free (GumFFIFunction, func);
}

static Handle<Value>
gum_script_core_on_new_native_callback (const Arguments & args)
{
  GumScriptCore * self =
      static_cast<GumScriptCore *> (External::Unwrap (args.Data ()));
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
  Persistent<Object> persistent_instance;

  callback = g_slice_new0 (GumFFICallback);
  callback->core = self;

  func_value = args[0];
  if (!func_value->IsFunction ())
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "first argument must be a function implementing the callback")));
    goto error;
  }
  callback->func = Persistent<Function>::New (
      Local<Function>::Cast (func_value));
  callback->receiver = Persistent<Object>::New (args.This ());

  rtype_value = args[1];
  if (!rtype_value->IsString ())
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "second argument must be a string specifying return type")));
    goto error;
  }
  if (!gum_script_ffi_type_get (rtype_value, &rtype))
    goto error;

  atypes_value = args[2];
  if (!atypes_value->IsArray ())
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "third argument must be an array specifying argument types")));
    goto error;
  }
  atypes_array = Array::Cast (*atypes_value);
  nargs = atypes_array->Length ();
  callback->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    if (!gum_script_ffi_type_get (atypes_array->Get (i), &callback->atypes[i]))
      goto error;
  }

  abi = FFI_DEFAULT_ABI;
  if (args.Length () > 3)
  {
    if (!gum_script_ffi_abi_get (args[3], &abi))
      goto error;
  }

  callback->closure = static_cast<ffi_closure *> (
      ffi_closure_alloc (sizeof (ffi_closure), &func));
  if (callback->closure == NULL)
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "failed to allocate closure")));
    goto error;
  }

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
        callback->atypes) != FFI_OK)
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "failed to compile function call interface")));
    goto error;
  }

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
        gum_script_core_on_invoke_native_callback, callback, func) != FFI_OK)
  {
    ThrowException (Exception::TypeError (String::New ("NativeCallback: "
        "failed to prepare closure")));
    goto error;
  }

  instance = args.Holder ();
  instance->SetPointerInInternalField (0, func);

  persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (func, gum_script_core_on_free_native_callback);
  persistent_instance.MarkIndependent ();

  return Undefined ();

error:
  gum_ffi_callback_free (callback);
  return Undefined ();
}

static void
gum_script_core_on_free_native_callback (Persistent<Value> object,
                                         void * data)
{
  HandleScope handle_scope;
  gum_ffi_callback_free (static_cast<GumFFICallback *> (data));
  object.Dispose ();
}

static void
gum_script_core_on_invoke_native_callback (ffi_cif * cif,
                                           void * return_value,
                                           void ** args,
                                           void * user_data)
{
  GumFFICallback * self = static_cast<GumFFICallback *> (user_data);
  ScriptScope scope (self->core->script);

  Local<Value> * argv = static_cast<Local<Value> *> (
      g_alloca (cif->nargs * sizeof (Local<Value>)));
  for (guint i = 0; i != cif->nargs; i++)
  {
    if (!gum_script_value_from_ffi_type (self->core, &argv[i],
          static_cast<GumFFIValue *> (args[i]), cif->arg_types[i]))
    {
      return;
    }
  }

  Local<Value> result = self->func->Call (self->receiver, cif->nargs, argv);
  if (cif->rtype != &ffi_type_void)
  {
    gum_script_value_to_ffi_type (self->core, result,
        static_cast<GumFFIValue *> (return_value), cif->rtype);
  }
}

static void
gum_ffi_callback_free (GumFFICallback * callback)
{
  callback->func.Dispose ();
  callback->receiver.Dispose ();
  ffi_closure_free (callback->closure);
  g_free (callback->atypes);

  g_slice_free (GumFFICallback, callback);
}

static GumMessageSink *
gum_message_sink_new (Handle<Function> callback,
                      Handle<Object> receiver)
{
  GumMessageSink * sink;

  sink = g_slice_new (GumMessageSink);
  sink->callback = Persistent<Function>::New (callback);
  sink->receiver = Persistent<Object>::New (receiver);

  return sink;
}

static void
gum_message_sink_free (GumMessageSink * sink)
{
  if (sink == NULL)
    return;

  sink->callback.Dispose ();
  sink->receiver.Dispose ();

  g_slice_free (GumMessageSink, sink);
}

static void
gum_message_sink_handle_message (GumMessageSink * self,
                                 const gchar * message)
{
  Handle<Value> argv[] = { String::New (message) };
  self->callback->Call (self->receiver, 1, argv);
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
  { "uint64", &ffi_type_uint64 }
};

static const GumFFIABIMapping gum_ffi_abi_mappings[] =
{
  { "default", FFI_DEFAULT_ABI },
#if defined (X86_WIN32)
  { "sysv", FFI_SYSV },
  { "stdcall", FFI_STDCALL },
  { "thiscall", FFI_THISCALL },
  { "fastcall", FFI_FASTCALL },
  { "mscdecl", FFI_MS_CDECL }
#elif defined (X86_WIN64)
  { "win64", FFI_WIN64 }
#elif defined (X86_ANY)
  { "sysv", FFI_SYSV },
  { "unix64", FFI_UNIX64 }
#elif defined (ARM)
  { "sysv", FFI_SYSV },
  { "vfp", FFI_VFP }
#endif
};

static gboolean
gum_script_ffi_type_get (Handle<Value> name,
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

  ThrowException (Exception::TypeError (
      String::New ("invalid type specified")));
  return FALSE;
}

static gboolean
gum_script_ffi_abi_get (Handle<Value> name,
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

  ThrowException (Exception::TypeError (
      String::New ("invalid abi specified")));
  return FALSE;
}

static gboolean
gum_script_value_to_ffi_type (GumScriptCore * self,
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
    if (!_gum_script_pointer_get (self, svalue, &value->v_pointer))
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
    ThrowException (Exception::TypeError (String::New (
        "value_to_ffi_type: unsupported type")));
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_script_value_from_ffi_type (GumScriptCore * self,
                                Handle<Value> * svalue,
                                const GumFFIValue * value,
                                const ffi_type * type)
{
  if (type == &ffi_type_void)
  {
    *svalue = Undefined ();
  }
  else if (type == &ffi_type_pointer)
  {
    *svalue = _gum_script_pointer_new (self, value->v_pointer);
  }
  else if (type == &ffi_type_sint)
  {
    *svalue = Number::New (value->v_sint);
  }
  else if (type == &ffi_type_uint)
  {
    *svalue = Number::New (value->v_uint);
  }
  else if (type == &ffi_type_slong)
  {
    *svalue = Number::New (value->v_slong);
  }
  else if (type == &ffi_type_ulong)
  {
    *svalue = Number::New (value->v_ulong);
  }
  else if (type == &ffi_type_schar)
  {
    *svalue = Integer::New (value->v_schar);
  }
  else if (type == &ffi_type_uchar)
  {
    *svalue = Integer::NewFromUnsigned (value->v_uchar);
  }
  else if (type == &ffi_type_float)
  {
    *svalue = Number::New (value->v_float);
  }
  else if (type == &ffi_type_double)
  {
    *svalue = Number::New (value->v_double);
  }
  else if (type == &ffi_type_sint8)
  {
    *svalue = Integer::New (value->v_sint8);
  }
  else if (type == &ffi_type_uint8)
  {
    *svalue = Integer::NewFromUnsigned (value->v_uint8);
  }
  else if (type == &ffi_type_sint16)
  {
    *svalue = Integer::New (value->v_sint16);
  }
  else if (type == &ffi_type_uint16)
  {
    *svalue = Integer::NewFromUnsigned (value->v_uint16);
  }
  else if (type == &ffi_type_sint32)
  {
    *svalue = Integer::New (value->v_sint32);
  }
  else if (type == &ffi_type_uint32)
  {
    *svalue = Integer::NewFromUnsigned (value->v_uint32);
  }
  else if (type == &ffi_type_sint64)
  {
    *svalue = Number::New (value->v_sint64);
  }
  else if (type == &ffi_type_uint64)
  {
    *svalue = Number::New (value->v_uint64);
  }
  else
  {
    ThrowException (Exception::TypeError (String::New (
        "value_from_ffi_type: unsupported type")));
    return FALSE;
  }

  return TRUE;
}

Handle<Object>
_gum_script_pointer_new (GumScriptCore * core,
                         gpointer address)
{
  Local<Object> native_pointer_object = core->native_pointer_value->Clone ();
  native_pointer_object->SetPointerInInternalField (0, address);
  return native_pointer_object;
}

gboolean
_gum_script_pointer_get (GumScriptCore * core,
                         Handle<Value> value,
                         gpointer * target)
{
  if (!core->native_pointer->HasInstance (value))
  {
    ThrowException (Exception::TypeError (String::New (
        "expected NativePointer object")));
    return FALSE;
  }
  *target = value->ToObject ()->GetPointerFromInternalField (0);

  return TRUE;
}

gboolean
_gum_script_callbacks_get (Handle<Object> callbacks,
                           const gchar * name,
                           Handle<Function> * callback_function)
{
  if (!_gum_script_callbacks_get_opt (callbacks, name, callback_function))
    return FALSE;

  if ((*callback_function).IsEmpty ())
  {
    gchar * message = g_strdup_printf ("%s callback is required", name);
    ThrowException (Exception::TypeError (String::New (message)));
    g_free (message);

    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_script_callbacks_get_opt (Handle<Object> callbacks,
                               const gchar * name,
                               Handle<Function> * callback_function)
{
  Local<Value> val = callbacks->Get (String::New (name));
  if (!val->IsUndefined ())
  {
    if (!val->IsFunction ())
    {
      gchar * message = g_strdup_printf ("%s must be a function", name);
      ThrowException (Exception::TypeError (String::New (message)));
      g_free (message);

      return FALSE;
    }

    *callback_function = Local<Function>::Cast (val);
  }

  return TRUE;
}

Handle<Object>
_gum_script_cpu_context_to_object (GumScriptCore * core,
                                   const GumCpuContext * ctx)
{
  Local<Object> result (Object::New ());
  gsize pc, sp;

#if defined (HAVE_ARM)
  pc = ctx->pc;
  sp = ctx->sp;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  pc = ctx->eip;
  sp = ctx->esp;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  pc = ctx->rip;
  sp = ctx->rsp;
#endif

  result->Set (String::New ("pc"),
      _gum_script_pointer_new (core, GSIZE_TO_POINTER (pc)), ReadOnly);
  result->Set (String::New ("sp"),
      _gum_script_pointer_new (core, GSIZE_TO_POINTER (sp)), ReadOnly);

  return result;
}

gboolean
_gum_script_page_protection_get (Handle<Value> prot_val,
                                 GumPageProtection * prot)
{
  if (!prot_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
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
        ThrowException (Exception::TypeError (String::New (
            "invalid character in memory protection specifier string")));
        return FALSE;
    }
  }

  return TRUE;
}

