/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
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

#include "gumscript.h"

#include "guminterceptor.h"
#include "gumprocess.h"
#include "gumscript-priv.h"
#include "gumscripteventsink.h"
#include "gumscriptpointer.h"
#include "gumscriptscope.h"
#include "gumtls.h"
#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#endif

#include <ffi.h>
#include <gio/gio.h>
#include <setjmp.h>
#include <string.h>
#include <v8.h>
#include <wchar.h>
#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
# define GUM_SETJMP(env) setjmp (env)
# define GUM_LONGJMP(env, val) longjmp (env, val)
  typedef jmp_buf gum_jmp_buf;
# define GUM_SOCKOPT_OPTVAL(v) reinterpret_cast<char *> (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# include <signal.h>
# include <stdlib.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/un.h>
# ifdef HAVE_DARWIN
#  define GUM_SETJMP(env) setjmp (env)
#  define GUM_LONGJMP(env, val) longjmp (env, val)
   typedef jmp_buf gum_jmp_buf;
# else
#  define GUM_SETJMP(env) sigsetjmp (env, 1)
#  define GUM_LONGJMP(env, val) siglongjmp (env, val)
   typedef sigjmp_buf gum_jmp_buf;
# endif
# if defined (HAVE_MAC) && GLIB_SIZEOF_VOID_P == 4
#  define GUM_INVALID_ACCESS_SIGNAL SIGBUS
# else
#  define GUM_INVALID_ACCESS_SIGNAL SIGSEGV
# endif
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ARCH "ia32"
# else
#  define GUM_SCRIPT_ARCH "x64"
# endif
#elif defined (HAVE_ARM)
# define GUM_SCRIPT_ARCH "arm"
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (G_OS_WIN32)
# define GUM_SCRIPT_PLATFORM "windows"
#endif

#define GUM_SCRIPT_RUNTIME_SOURCE_LINE_COUNT 1

using namespace v8;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumMessageSink GumMessageSink;
typedef struct _GumScriptAttachEntry GumScriptAttachEntry;
typedef struct _GumMemoryAccessScope GumMemoryAccessScope;
typedef guint GumMemoryValueType;

typedef struct _GumScriptMatchContext GumScriptMatchContext;
typedef struct _GumMemoryScanContext GumMemoryScanContext;
typedef struct _GumScriptCallProbe GumScriptCallProbe;

typedef struct _GumFFIFunction GumFFIFunction;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumScriptPrivate
{
  GMainContext * main_context;

  GumInterceptor * interceptor;
  GumStalker * stalker;
  GumEventSink * stalker_sink;
  guint stalker_queue_capacity;
  guint stalker_queue_drain_interval;
  gint stalker_pending_follow_level;

  Isolate * isolate;
  Persistent<Context> context;
  Persistent<Script> raw_script;
  Persistent<FunctionTemplate> native_pointer;
  Persistent<Object> native_pointer_value;
  Persistent<ObjectTemplate> invocation_args;
  Persistent<ObjectTemplate> probe_args;

  GumScriptMessageHandler message_handler_func;
  gpointer message_handler_data;
  GDestroyNotify message_handler_notify;

  GMutex * mutex;

  GCond * event_cond;
  guint event_count;

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  GumMessageSink * incoming_message_sink;

  GQueue * attach_entries;
};

struct _GumScheduledCallback
{
  gint id;
  gboolean repeat;
  Persistent<Function> func;
  Persistent<Object> receiver;
  GSource * source;
  GumScript * script;
};

struct _GumMessageSink
{
  Persistent<Function> callback;
  Persistent<Object> receiver;
};

struct _GumScriptAttachEntry
{
  Persistent<Function> on_enter;
  Persistent<Function> on_leave;
};

struct _GumMemoryAccessScope
{
  gboolean exception_occurred;
  gpointer address;
  gum_jmp_buf env;
};
#define GUM_MEMORY_ACCESS_SCOPE_INIT { FALSE, NULL, }

enum _GumMemoryValueType
{
  GUM_MEMORY_VALUE_POINTER,
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct _GumScriptMatchContext
{
  GumScript * script;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

struct _GumMemoryScanContext
{
  GumScript * script;
  GumMemoryRange range;
  GumMatchPattern * pattern;
  Persistent<Function> on_match;
  Persistent<Function> on_error;
  Persistent<Function> on_complete;
  Persistent<Object> receiver;
};

struct _GumScriptCallProbe
{
  GumScript * script;
  Persistent<Function> callback;
  Persistent<Object> receiver;
};

struct _GumFFIFunction
{
  gpointer fn;
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

static void gum_script_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_script_dispose (GObject * object);
static void gum_script_finalize (GObject * object);
static void gum_script_create_context (GumScript * self);

static Handle<Value> gum_script_on_console_log (const Arguments & args);
static Handle<Value> gum_script_on_set_timeout (const Arguments & args);
static Handle<Value> gum_script_on_set_interval (const Arguments & args);
static Handle<Value> gum_script_on_clear_timeout (const Arguments & args);
static GumScheduledCallback * gum_scheduled_callback_new (gint id,
    gboolean repeat, GSource * source, GumScript * script);
static void gum_scheduled_callback_free (GumScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);
static Handle<Value> gum_script_on_send (const Arguments & args);
static Handle<Value> gum_script_on_set_incoming_message_callback (
    const Arguments & args);
static Handle<Value> gum_script_on_wait_for_event (const Arguments & args);

static Handle<Value> gum_script_on_new_native_pointer (const Arguments & args);
static Handle<Value> gum_script_on_native_pointer_add (const Arguments & args);
static Handle<Value> gum_script_on_native_pointer_sub (const Arguments & args);
static Handle<Value> gum_script_on_native_pointer_to_int32 (
    const Arguments & args);
static Handle<Value> gum_script_on_native_pointer_to_string (
    const Arguments & args);
static Handle<Value> gum_script_on_native_pointer_to_json (
    const Arguments & args);

static Handle<Value> gum_script_on_new_native_function (
    const Arguments & args);
static void gum_script_on_free_native_function (Persistent<Value> object,
    void * data);
static Handle<Value> gum_script_on_invoke_native_function (
    const Arguments & args);
static void gum_ffi_function_free (GumFFIFunction * func);

static GumMessageSink * gum_message_sink_new (Handle<Function> callback,
    Handle<Object> receiver);
static void gum_message_sink_free (GumMessageSink * sink);
static void gum_message_sink_handle_message (GumMessageSink * self,
    const gchar * message);
static Handle<Value> gum_script_on_process_get_current_thread_id (
    const Arguments & args);
static Handle<Value> gum_script_on_process_enumerate_threads (
    const Arguments & args);
static gboolean gum_script_process_thread_match (GumThreadDetails * details,
    gpointer user_data);
static const gchar * gum_script_thread_state_to_string (GumThreadState state);
static Handle<Object> gum_script_cpu_context_to_object (GumScript * self,
    const GumCpuContext * ctx);
static Handle<Value> gum_script_on_process_enumerate_modules (
    const Arguments & args);
static gboolean gum_script_process_module_match (const gchar * name,
    const GumMemoryRange * range, const gchar * path, gpointer user_data);
static Handle<Value> gum_script_on_process_enumerate_ranges (
    const Arguments & args);
static gboolean gum_script_range_match (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);
static Handle<Value> gum_script_on_thread_sleep (const Arguments & args);
static Handle<Value> gum_script_on_module_enumerate_exports (
    const Arguments & args);
static Handle<Value> gum_script_on_module_enumerate_ranges (
    const Arguments & args);
static gboolean gum_script_module_export_match (const gchar * name,
    GumAddress address, gpointer user_data);
static Handle<Value> gum_script_on_module_find_base_address (
    const Arguments & args);
static Handle<Value> gum_script_on_module_find_export_by_name (
    const Arguments & args);
static Handle<Value> gum_script_on_interceptor_attach (const Arguments & args);

#ifdef G_OS_WIN32
static gboolean gum_script_memory_on_exception (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);
#else
static void gum_script_memory_on_invalid_access (int sig, siginfo_t * siginfo,
    void * context);
#endif

static Handle<Value> gum_script_on_memory_scan (const Arguments & args);
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static gboolean gum_script_do_memory_scan (GIOSchedulerJob * job,
    GCancellable * cancellable, gpointer user_data);
static gboolean gum_script_process_scan_match (GumAddress address, gsize size,
    gpointer user_data);

static Handle<Value> gum_script_on_memory_alloc (const Arguments & args);
static void gum_script_on_free_malloc_pointer (Persistent<Value> object,
    void * data);
static Handle<Value> gum_script_on_memory_read_pointer (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_write_pointer (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_read_s8 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_u8 (const Arguments & args);
static Handle<Value> gum_script_on_memory_write_u8 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_s16 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_u16 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_s32 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_u32 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_s64 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_u64 (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_byte_array (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_read_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_write_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_read_utf16_string (
    const Arguments & args);
#ifdef G_OS_WIN32
static Handle<Value> gum_script_on_memory_read_ansi_string (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_alloc_ansi_string (
    const Arguments & args);
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif
static Handle<Value> gum_script_on_memory_alloc_utf8_string (
    const Arguments & args);
static Handle<Value> gum_script_on_memory_alloc_utf16_string (
    const Arguments & args);
static Handle<Value> gum_script_on_socket_type (const Arguments & args);
static Handle<Value> gum_script_on_socket_local_address (
    const Arguments & args);
static Handle<Value> gum_script_on_socket_peer_address (const Arguments & args);
static Handle<Value> gum_script_socket_address_to_value (
    struct sockaddr * addr);
static Handle<Value> gum_script_on_stalker_get_trust_threshold (
    Local<String> property, const AccessorInfo & info);
static void gum_script_on_stalker_set_trust_threshold (Local<String> property,
    Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_on_stalker_get_queue_capacity (
    Local<String> property, const AccessorInfo & info);
static void gum_script_on_stalker_set_queue_capacity (Local<String> property,
    Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_on_stalker_get_queue_drain_interval (
    Local<String> property, const AccessorInfo & info);
static void gum_script_on_stalker_set_queue_drain_interval (
    Local<String> property, Local<Value> value, const AccessorInfo & info);
static Handle<Value> gum_script_on_stalker_garbage_collect (
    const Arguments & args);
static Handle<Value> gum_script_on_stalker_follow (const Arguments & args);
static Handle<Value> gum_script_on_stalker_unfollow (const Arguments & args);
static Handle<Value> gum_script_on_stalker_add_call_probe (
    const Arguments & args);
static Handle<Value> gum_script_on_stalker_remove_call_probe (
    const Arguments & args);
static void gum_script_call_probe_free (GumScriptCallProbe * probe);
static void gum_script_call_probe_fire (GumCallSite * site,
    gpointer user_data);
static Handle<Value> gum_script_probe_args_on_get_nth (uint32_t index,
    const AccessorInfo & info);

static void gum_script_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_script_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static Handle<Value> gum_script_invocation_args_on_get_nth (uint32_t index,
    const AccessorInfo & info);
static Handle<Value> gum_script_invocation_args_on_set_nth (uint32_t index,
    Local<Value> value, const AccessorInfo & info);

static gboolean gum_script_ffi_type_get (Handle<Value> name, ffi_type ** type);
static gboolean gum_script_ffi_abi_get (Handle<Value> name, ffi_abi * abi);
static gboolean gum_script_value_to_ffi_type (GumScript * self,
    const Handle<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_script_value_from_ffi_type (GumScript * self,
    Handle<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

static gboolean gum_script_callbacks_get (Handle<Object> callbacks,
    const gchar * name, Handle<Function> * callback_function);
static gboolean gum_script_callbacks_get_opt (Handle<Object> callbacks,
    const gchar * name, Handle<Function> * callback_function);
static gboolean gum_script_flags_get (Handle<Object> flags,
    const gchar * name);
static gboolean gum_script_page_protection_get (Handle<Value> prot_val,
    GumPageProtection * prot);

G_DEFINE_TYPE_EXTENDED (GumScript,
                        gum_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_script_listener_iface_init));

G_LOCK_DEFINE_STATIC (gum_memaccess);
static guint gum_memaccess_refcount = 0;
static GumTlsKey gum_memaccess_scope_tls;
#ifndef G_OS_WIN32
static struct sigaction gum_memaccess_old_action;
#endif

static const gchar * gum_script_runtime_source =
#include "gumscript-runtime.h"
;

void
_gum_script_init (void)
{
  V8::Initialize ();
}

void
_gum_script_deinit (void)
{
  V8::Dispose ();
}

static void
gum_script_class_init (GumScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptPrivate));

  object_class->dispose = gum_script_dispose;
  object_class->finalize = gum_script_finalize;
}

static void
gum_script_listener_iface_init (gpointer g_iface,
                                gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_script_on_enter;
  iface->on_leave = gum_script_on_leave;
}

static void
gum_script_init (GumScript * self)
{
  GumScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_SCRIPT, GumScriptPrivate);

  priv->main_context = g_main_context_get_thread_default ();

  priv->interceptor = gum_interceptor_obtain ();
  priv->stalker = NULL;
  priv->stalker_sink = NULL;
  priv->stalker_queue_capacity = 16384;
  priv->stalker_queue_drain_interval = 250;
  priv->stalker_pending_follow_level = 0;

  priv->mutex = g_mutex_new ();

  priv->event_cond = g_cond_new ();

  priv->attach_entries = g_queue_new ();

  G_LOCK (gum_memaccess);
  if (gum_memaccess_refcount++ == 0)
  {
    GUM_TLS_KEY_INIT (&gum_memaccess_scope_tls);

#ifndef G_OS_WIN32
    struct sigaction action;
    action.sa_sigaction = gum_script_memory_on_invalid_access;
    sigemptyset (&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    sigaction (GUM_INVALID_ACCESS_SIGNAL, &action, &gum_memaccess_old_action);
#endif
  }
  G_UNLOCK (gum_memaccess);

#ifdef G_OS_WIN32
  gum_win_exception_hook_add (gum_script_memory_on_exception, self);
#endif

  priv->isolate = Isolate::New ();

  gum_script_create_context (self);
}

static void
gum_script_dispose (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

#ifdef G_OS_WIN32
  gum_win_exception_hook_remove (gum_script_memory_on_exception);
#endif

  if (priv->interceptor != NULL)
  {
    {
      Locker locker(priv->isolate);
      Isolate::Scope isolate_scope(priv->isolate);
      HandleScope handle_scope;
      Context::Scope context_scope (priv->context);

      gum_script_unload (self);

      priv->main_context = NULL;

      priv->stalker_sink = NULL;
      if (priv->stalker != NULL)
      {
        g_object_unref (priv->stalker);
        priv->stalker = NULL;
      }

      g_object_unref (priv->interceptor);
      priv->interceptor = NULL;

      while (priv->scheduled_callbacks != NULL)
      {
        g_source_destroy (static_cast<GumScheduledCallback *> (
            priv->scheduled_callbacks->data)->source);
        priv->scheduled_callbacks = g_slist_delete_link (
            priv->scheduled_callbacks, priv->scheduled_callbacks);
      }

      gum_message_sink_free (priv->incoming_message_sink);
      priv->incoming_message_sink = NULL;

      while (!g_queue_is_empty (priv->attach_entries))
      {
        GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
            g_queue_pop_tail (priv->attach_entries));
        entry->on_enter.Dispose ();
        entry->on_leave.Dispose ();
        g_slice_free (GumScriptAttachEntry, entry);
      }

      priv->native_pointer_value.Dispose ();
      priv->native_pointer_value.Clear ();
      priv->native_pointer.Dispose ();
      priv->native_pointer.Clear ();
      priv->invocation_args.Dispose ();
      priv->invocation_args.Clear ();
      priv->probe_args.Dispose ();
      priv->probe_args.Clear ();
      priv->raw_script.Dispose ();
      priv->raw_script.Clear ();
      priv->context.Dispose ();
      priv->context.Clear ();
    }

    priv->isolate->Dispose ();
    priv->isolate = NULL;
  }

  G_OBJECT_CLASS (gum_script_parent_class)->dispose (object);
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler_notify != NULL)
    priv->message_handler_notify (priv->message_handler_data);

  G_LOCK (gum_memaccess);
  if (--gum_memaccess_refcount == 0)
  {
#ifndef G_OS_WIN32
    sigaction (GUM_INVALID_ACCESS_SIGNAL, &gum_memaccess_old_action, NULL);
    memset (&gum_memaccess_old_action, 0, sizeof (gum_memaccess_old_action));
#endif

    GUM_TLS_KEY_FREE (gum_memaccess_scope_tls);
    gum_memaccess_scope_tls = 0;
  }
  G_UNLOCK (gum_memaccess);

  g_mutex_free (priv->mutex);

  g_cond_free (priv->event_cond);

  g_queue_free (priv->attach_entries);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

static void
gum_script_create_context (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;
  Locker locker (priv->isolate);
  Isolate::Scope isolate_scope (priv->isolate);
  HandleScope handle_scope;

  Handle<ObjectTemplate> global_templ = ObjectTemplate::New ();

  Handle<ObjectTemplate> console_templ = ObjectTemplate::New ();
  console_templ->Set (String::New ("log"), FunctionTemplate::New (
      gum_script_on_console_log, External::Wrap (self)));
  global_templ->Set (String::New ("console"), console_templ);

  global_templ->Set (String::New ("setTimeout"),
      FunctionTemplate::New (gum_script_on_set_timeout, External::Wrap (self)));
  global_templ->Set (String::New ("setInterval"),
      FunctionTemplate::New (gum_script_on_set_interval,
          External::Wrap (self)));
  global_templ->Set (String::New ("clearTimeout"),
      FunctionTemplate::New (gum_script_on_clear_timeout,
          External::Wrap (self)));
  global_templ->Set (String::New ("clearInterval"),
      FunctionTemplate::New (gum_script_on_clear_timeout,
          External::Wrap (self)));
  global_templ->Set (String::New ("_send"),
      FunctionTemplate::New (gum_script_on_send, External::Wrap (self)));
  global_templ->Set (String::New ("_setIncomingMessageCallback"),
      FunctionTemplate::New (gum_script_on_set_incoming_message_callback,
          External::Wrap (self)));
  global_templ->Set (String::New ("_waitForEvent"),
      FunctionTemplate::New (gum_script_on_wait_for_event,
          External::Wrap (self)));

  Local<FunctionTemplate> native_pointer = FunctionTemplate::New (
      gum_script_on_new_native_pointer);
  native_pointer->SetClassName (String::New ("NativePointer"));
  Local<ObjectTemplate> native_pointer_object =
      native_pointer->InstanceTemplate ();
  native_pointer_object->SetInternalFieldCount (1);
  native_pointer_object->Set (String::New ("add"),
      FunctionTemplate::New (gum_script_on_native_pointer_add,
      External::Wrap (self)));
  native_pointer_object->Set (String::New ("sub"),
      FunctionTemplate::New (gum_script_on_native_pointer_sub,
      External::Wrap (self)));
  native_pointer_object->Set (String::New ("toInt32"),
      FunctionTemplate::New (gum_script_on_native_pointer_to_int32));
  native_pointer_object->Set (String::New ("toString"),
      FunctionTemplate::New (gum_script_on_native_pointer_to_string));
  native_pointer_object->Set (String::New ("toJSON"),
      FunctionTemplate::New (gum_script_on_native_pointer_to_json));
  global_templ->Set (String::New ("NativePointer"), native_pointer);
  priv->native_pointer = Persistent<FunctionTemplate>::New (native_pointer);

  Local<FunctionTemplate> native_function = FunctionTemplate::New (
      gum_script_on_new_native_function, External::Wrap (self));
  native_function->SetClassName (String::New ("NativeFunction"));
  Local<ObjectTemplate> native_function_object =
      native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gum_script_on_invoke_native_function, External::Wrap (self));
  native_function_object->SetInternalFieldCount (1);
  global_templ->Set (String::New ("NativeFunction"), native_function);

  Handle<ObjectTemplate> interceptor_templ = ObjectTemplate::New ();
  interceptor_templ->Set (String::New ("attach"), FunctionTemplate::New (
      gum_script_on_interceptor_attach, External::Wrap (self)));
  global_templ->Set (String::New ("Interceptor"), interceptor_templ);

  Handle<ObjectTemplate> process_templ = ObjectTemplate::New ();
  process_templ->Set (String::New ("arch"),
      String::New (GUM_SCRIPT_ARCH), ReadOnly);
  process_templ->Set (String::New ("platform"),
      String::New (GUM_SCRIPT_PLATFORM), ReadOnly);
  process_templ->Set (String::New ("getCurrentThreadId"),
      FunctionTemplate::New (gum_script_on_process_get_current_thread_id));
  process_templ->Set (String::New ("enumerateThreads"),
      FunctionTemplate::New (gum_script_on_process_enumerate_threads,
      External::Wrap (self)));
  process_templ->Set (String::New ("enumerateModules"),
      FunctionTemplate::New (gum_script_on_process_enumerate_modules,
      External::Wrap (self)));
  process_templ->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_on_process_enumerate_ranges,
      External::Wrap (self)));
  global_templ->Set (String::New ("Process"), process_templ);

  Handle<ObjectTemplate> thread_templ = ObjectTemplate::New ();
  thread_templ->Set (String::New ("sleep"),
      FunctionTemplate::New (gum_script_on_thread_sleep));
  global_templ->Set (String::New ("Thread"), thread_templ);

  Handle<ObjectTemplate> module_templ = ObjectTemplate::New ();
  module_templ->Set (String::New ("enumerateExports"),
      FunctionTemplate::New (gum_script_on_module_enumerate_exports,
      External::Wrap (self)));
  module_templ->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_on_module_enumerate_ranges,
      External::Wrap (self)));
  module_templ->Set (String::New ("findBaseAddress"),
      FunctionTemplate::New (gum_script_on_module_find_base_address,
      External::Wrap (self)));
  module_templ->Set (String::New ("findExportByName"),
      FunctionTemplate::New (gum_script_on_module_find_export_by_name,
      External::Wrap (self)));
  global_templ->Set (String::New ("Module"), module_templ);

  Handle<ObjectTemplate> memory_templ = ObjectTemplate::New ();
  memory_templ->Set (String::New ("scan"),
      FunctionTemplate::New (gum_script_on_memory_scan,
          External::Wrap (self)));
  memory_templ->Set (String::New ("alloc"),
      FunctionTemplate::New (gum_script_on_memory_alloc,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readPointer"),
      FunctionTemplate::New (gum_script_on_memory_read_pointer,
          External::Wrap (self)));
  memory_templ->Set (String::New ("writePointer"),
      FunctionTemplate::New (gum_script_on_memory_write_pointer,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readS8"),
      FunctionTemplate::New (gum_script_on_memory_read_s8,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readU8"),
      FunctionTemplate::New (gum_script_on_memory_read_u8,
          External::Wrap (self)));
  memory_templ->Set (String::New ("writeU8"),
      FunctionTemplate::New (gum_script_on_memory_write_u8,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readS16"),
      FunctionTemplate::New (gum_script_on_memory_read_s16,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readU16"),
      FunctionTemplate::New (gum_script_on_memory_read_u16,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readS32"),
      FunctionTemplate::New (gum_script_on_memory_read_s32,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readU32"),
      FunctionTemplate::New (gum_script_on_memory_read_u32,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readS64"),
      FunctionTemplate::New (gum_script_on_memory_read_s64,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readU64"),
      FunctionTemplate::New (gum_script_on_memory_read_u64,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readByteArray"),
      FunctionTemplate::New (gum_script_on_memory_read_byte_array,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readUtf8String"),
      FunctionTemplate::New (gum_script_on_memory_read_utf8_string,
          External::Wrap (self)));
  memory_templ->Set (String::New ("writeUtf8String"),
      FunctionTemplate::New (gum_script_on_memory_write_utf8_string,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readUtf16String"),
      FunctionTemplate::New (gum_script_on_memory_read_utf16_string,
          External::Wrap (self)));
#ifdef G_OS_WIN32
  memory_templ->Set (String::New ("readAnsiString"),
      FunctionTemplate::New (gum_script_on_memory_read_ansi_string,
          External::Wrap (self)));
  memory_templ->Set (String::New ("allocAnsiString"),
      FunctionTemplate::New (gum_script_on_memory_alloc_ansi_string,
          External::Wrap (self)));
#endif
  memory_templ->Set (String::New ("allocUtf8String"),
      FunctionTemplate::New (gum_script_on_memory_alloc_utf8_string,
          External::Wrap (self)));
  memory_templ->Set (String::New ("allocUtf16String"),
      FunctionTemplate::New (gum_script_on_memory_alloc_utf16_string,
          External::Wrap (self)));
  global_templ->Set (String::New ("Memory"), memory_templ);

  Handle<ObjectTemplate> socket_templ = ObjectTemplate::New ();
  socket_templ->Set (String::New ("type"),
      FunctionTemplate::New (gum_script_on_socket_type));
  socket_templ->Set (String::New ("localAddress"),
      FunctionTemplate::New (gum_script_on_socket_local_address));
  socket_templ->Set (String::New ("peerAddress"),
      FunctionTemplate::New (gum_script_on_socket_peer_address));
  global_templ->Set (String::New ("Socket"), socket_templ);

  Handle<ObjectTemplate> stalker_templ = ObjectTemplate::New ();
  stalker_templ->SetAccessor (String::New ("trustThreshold"),
      gum_script_on_stalker_get_trust_threshold,
      gum_script_on_stalker_set_trust_threshold,
      External::Wrap (self));
  stalker_templ->SetAccessor (String::New ("queueCapacity"),
      gum_script_on_stalker_get_queue_capacity,
      gum_script_on_stalker_set_queue_capacity,
      External::Wrap (self));
  stalker_templ->SetAccessor (String::New ("queueDrainInterval"),
      gum_script_on_stalker_get_queue_drain_interval,
      gum_script_on_stalker_set_queue_drain_interval,
      External::Wrap (self));
  stalker_templ->Set (String::New ("garbageCollect"),
      FunctionTemplate::New (gum_script_on_stalker_garbage_collect,
          External::Wrap (self)));
  stalker_templ->Set (String::New ("follow"),
      FunctionTemplate::New (gum_script_on_stalker_follow,
          External::Wrap (self)));
  stalker_templ->Set (String::New ("unfollow"),
      FunctionTemplate::New (gum_script_on_stalker_unfollow,
          External::Wrap (self)));
  stalker_templ->Set (String::New ("addCallProbe"),
      FunctionTemplate::New (gum_script_on_stalker_add_call_probe,
          External::Wrap (self)));
  stalker_templ->Set (String::New ("removeCallProbe"),
      FunctionTemplate::New (gum_script_on_stalker_remove_call_probe,
          External::Wrap (self)));
  global_templ->Set (String::New ("Stalker"), stalker_templ);

  priv->context = Context::New (NULL, global_templ);

  Context::Scope context_scope (priv->context);

  {
    priv->native_pointer_value = Persistent<Object>::New (
        priv->native_pointer->InstanceTemplate ()->NewInstance ());
  }

  {
    Handle<ObjectTemplate> args_templ = ObjectTemplate::New ();
    args_templ->SetInternalFieldCount (1);
    args_templ->SetIndexedPropertyHandler (
        gum_script_invocation_args_on_get_nth,
        gum_script_invocation_args_on_set_nth,
        0, 0, 0,
        External::Wrap (self));
    priv->invocation_args = Persistent<ObjectTemplate>::New (args_templ);
  }

  {
    Handle<ObjectTemplate> args_templ = ObjectTemplate::New ();
    args_templ->SetInternalFieldCount (2);
    args_templ->SetIndexedPropertyHandler (gum_script_probe_args_on_get_nth);
    priv->probe_args = Persistent<ObjectTemplate>::New (args_templ);
  }
}

class ScriptScopeImpl
{
public:
  ScriptScopeImpl (GumScript * parent)
    : parent (parent),
      locker (parent->priv->isolate),
      isolate_scope (parent->priv->isolate),
      context_scope (parent->priv->context)
  {
  }

  ~ScriptScopeImpl ()
  {
    GumScriptPrivate * priv = parent->priv;

    if (trycatch.HasCaught () && priv->message_handler_func != NULL)
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::AsciiValue exception_str (exception);
      gchar * error = g_strdup_printf (
          "{\"type\":\"error\",\"lineNumber\":%d,\"description\":\"%s\"}",
          message->GetLineNumber () - GUM_SCRIPT_RUNTIME_SOURCE_LINE_COUNT,
          *exception_str);
      priv->message_handler_func (parent, error, NULL, 0,
          priv->message_handler_data);
      g_free (error);
    }
  }

private:
  GumScript * parent;
  v8::Locker locker;
  v8::Isolate::Scope isolate_scope;
  v8::HandleScope handle_scope;
  v8::Context::Scope context_scope;
  v8::TryCatch trycatch;
};

ScriptScope::ScriptScope (GumScript * parent)
  : parent (parent),
    impl (new ScriptScopeImpl (parent))
{
}

ScriptScope::~ScriptScope ()
{
  GumScriptPrivate * priv = parent->priv;

  delete impl;
  impl = NULL;

  if (priv->stalker_pending_follow_level > 0)
  {
    gum_stalker_follow_me (gum_script_get_stalker (parent), priv->stalker_sink);
  }
  else if (priv->stalker_pending_follow_level < 0)
  {
    gum_stalker_unfollow_me (gum_script_get_stalker (parent));
  }
  priv->stalker_pending_follow_level = 0;

  if (priv->stalker_sink != NULL)
  {
    g_object_unref (priv->stalker_sink);
    priv->stalker_sink = NULL;
  }
}

GumScript *
gum_script_from_string (const gchar * source,
                        GError ** error)
{
  GumScript * script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
  GumScriptPrivate * priv = script->priv;

  {
    Locker locker(priv->isolate);
    Isolate::Scope isolate_scope(priv->isolate);
    HandleScope handle_scope;
    Context::Scope context_scope (priv->context);

    gchar * combined_source = g_strconcat (gum_script_runtime_source, "\n",
        source, NULL);
    Handle<String> source_value = String::New (combined_source);
    g_free (combined_source);
    TryCatch trycatch;
    Handle<Script> raw_script = Script::Compile (source_value);
    if (raw_script.IsEmpty ())
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::AsciiValue exception_str (exception);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber () - GUM_SCRIPT_RUNTIME_SOURCE_LINE_COUNT,
          *exception_str);
    }
    else
    {
      priv->raw_script = Persistent<Script>::New (raw_script);
    }
  }

  if (priv->raw_script.IsEmpty ())
  {
    g_object_unref (script);
    script = NULL;
  }

  return script;
}

GumStalker *
gum_script_get_stalker (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;

  if (priv->stalker == NULL)
    priv->stalker = gum_stalker_new ();

  return priv->stalker;
}

void
gum_script_set_message_handler (GumScript * self,
                                GumScriptMessageHandler func,
                                gpointer data,
                                GDestroyNotify notify)
{
  self->priv->message_handler_func = func;
  self->priv->message_handler_data = data;
  self->priv->message_handler_notify = notify;
}

void
gum_script_load (GumScript * self)
{
  ScriptScope scope (self);

  self->priv->raw_script->Run ();
}

void
gum_script_unload (GumScript * self)
{
  gum_interceptor_detach_listener (self->priv->interceptor,
      GUM_INVOCATION_LISTENER (self));
}

void
gum_script_post_message (GumScript * self,
                         const gchar * message)
{
  if (self->priv->incoming_message_sink != NULL)
  {
    GumScriptPrivate * priv = self->priv;

    {
      ScriptScope scope (self);
      gum_message_sink_handle_message (self->priv->incoming_message_sink,
          message);
      priv->event_count++;
    }

    g_mutex_lock (priv->mutex);
    g_cond_broadcast (priv->event_cond);
    g_mutex_unlock (priv->mutex);
  }
}

static Handle<Value>
gum_script_on_console_log (const Arguments & args)
{
  String::Utf8Value message (args[0]);
  g_print ("%s\n", *message);

  return Undefined ();
}

static void
gum_script_add_scheduled_callback (GumScript * self,
                                   GumScheduledCallback * callback)
{
  GumScriptPrivate * priv = self->priv;

  g_mutex_lock (priv->mutex);
  priv->scheduled_callbacks =
      g_slist_prepend (priv->scheduled_callbacks, callback);
  g_mutex_unlock (priv->mutex);
}

static void
gum_script_remove_scheduled_callback (GumScript * self,
                                      GumScheduledCallback * callback)
{
  GumScriptPrivate * priv = self->priv;

  g_mutex_lock (priv->mutex);
  priv->scheduled_callbacks =
      g_slist_remove (priv->scheduled_callbacks, callback);
  g_mutex_unlock (priv->mutex);
}

static Handle<Value>
gum_script_on_schedule_callback (const Arguments & args,
                                 gboolean repeat)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

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

  gint id = g_atomic_int_exchange_and_add (&priv->last_callback_id, 1) + 1;
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
  gum_script_add_scheduled_callback (self, callback);

  g_source_attach (source, priv->main_context);

  return Int32::New (id);
}

static Handle<Value>
gum_script_on_set_timeout (const Arguments & args)
{
  return gum_script_on_schedule_callback (args, FALSE);
}

static Handle<Value>
gum_script_on_set_interval (const Arguments & args)
{
  return gum_script_on_schedule_callback (args, TRUE);
}

static Handle<Value>
gum_script_on_clear_timeout (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;
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
  g_mutex_lock (priv->mutex);
  for (cur = priv->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumScheduledCallback * cb =
        static_cast<GumScheduledCallback *> (cur->data);
    if (cb->id == id)
    {
      callback = cb;
      priv->scheduled_callbacks =
          g_slist_delete_link (priv->scheduled_callbacks, cur);
      break;
    }
  }
  g_mutex_unlock (priv->mutex);

  if (callback != NULL)
    g_source_destroy (callback->source);

  return (callback != NULL) ? True () : False ();
}

static GumScheduledCallback *
gum_scheduled_callback_new (gint id,
                            gboolean repeat,
                            GSource * source,
                            GumScript * script)
{
  GumScheduledCallback * callback;

  callback = g_slice_new (GumScheduledCallback);
  callback->id = id;
  callback->repeat = repeat;
  callback->source = source;
  callback->script = script;

  return callback;
}

static void
gum_scheduled_callback_free (GumScheduledCallback * callback)
{
  Isolate * isolate = callback->script->priv->isolate;
  Locker locker(isolate);
  Isolate::Scope isolate_scope(isolate);
  HandleScope handle_scope;
  callback->func.Dispose ();
  callback->receiver.Dispose ();

  g_slice_free (GumScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumScheduledCallback * self =
      static_cast<GumScheduledCallback *> (user_data);

  ScriptScope scope (self->script);
  self->func->Call (self->receiver, 0, 0);

  if (!self->repeat)
    gum_script_remove_scheduled_callback (self->script, self);

  return self->repeat;
}

static Handle<Value>
gum_script_on_send (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler_func != NULL)
  {
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
      }
    }

    priv->message_handler_func (self, *message, data, data_length,
        priv->message_handler_data);
  }

  return Undefined ();
}

static Handle<Value>
gum_script_on_set_incoming_message_callback (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  if (args.Length () > 1)
  {
    ThrowException (Exception::TypeError (String::New (
        "invalid argument count")));
    return Undefined ();
  }

  gum_message_sink_free (priv->incoming_message_sink);
  priv->incoming_message_sink = NULL;

  if (args.Length () == 1)
  {
    priv->incoming_message_sink =
        gum_message_sink_new (Local<Function>::Cast (args[0]), args.This ());
  }

  return Undefined ();
}

static Handle<Value>
gum_script_on_wait_for_event (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;
  guint start_count;

  start_count = priv->event_count;
  while (priv->event_count == start_count)
  {
    Unlocker ul(priv->isolate);

    g_mutex_lock (priv->mutex);
    g_cond_wait (priv->event_cond, priv->mutex);
    g_mutex_unlock (priv->mutex);
  }

  return Undefined ();
}

static Handle<Value>
gum_script_on_new_native_pointer (const Arguments & args)
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
gum_script_on_native_pointer_add (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  guint64 lhs = reinterpret_cast<guint64> (
      args.Holder ()->GetPointerFromInternalField (0));
  if (self->priv->native_pointer->HasInstance (args[0]))
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
gum_script_on_native_pointer_sub (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  guint64 lhs = reinterpret_cast<guint64> (
      args.Holder ()->GetPointerFromInternalField (0));
  if (self->priv->native_pointer->HasInstance (args[0]))
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
gum_script_on_native_pointer_to_int32 (const Arguments & args)
{
  return Integer::New (static_cast<int32_t>
      (GPOINTER_TO_SIZE (args.Holder ()->GetPointerFromInternalField (0))));
}

static Handle<Value>
gum_script_on_native_pointer_to_string (const Arguments & args)
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
gum_script_on_native_pointer_to_json (const Arguments & args)
{
  gsize ptr = GPOINTER_TO_SIZE (
      args.Holder ()->GetPointerFromInternalField (0));

  gchar buf[32];
  sprintf (buf, "0x%" G_GSIZE_MODIFIER "x", ptr);

  return String::New (buf);
}

static Handle<Value>
gum_script_on_new_native_function (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumFFIFunction * func;
  Local<Value> rtype_value;
  ffi_type * rtype;
  Local<Value> atypes_value;
  Local<Array> atypes_array;
  uint32_t nargs, i;
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
  nargs = atypes_array->Length ();
  func->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    if (!gum_script_ffi_type_get (atypes_array->Get (i), &func->atypes[i]))
      goto error;
  }

  abi = FFI_DEFAULT_ABI;
  if (args.Length () > 3)
  {
    if (!gum_script_ffi_abi_get (args[3], &abi))
      goto error;
  }

  if (ffi_prep_cif (&func->cif, abi, nargs, rtype, func->atypes) != FFI_OK)
  {
    ThrowException (Exception::TypeError (String::New ("NativeFunction: "
        "failed to compile function call interface")));
    goto error;
  }

  instance = args.Holder ();
  instance->SetPointerInInternalField (0, func);

  persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (func, gum_script_on_free_native_function);
  persistent_instance.MarkIndependent ();

  return Undefined ();

error:
  gum_ffi_function_free (func);
  return Undefined ();
}

static void
gum_script_on_free_native_function (Persistent<Value> object,
                                    void * data)
{
  HandleScope handle_scope;
  gum_ffi_function_free (static_cast<GumFFIFunction *> (data));
  object.Dispose ();
}

static Handle<Value>
gum_script_on_invoke_native_function (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  Local<Object> instance = args.Holder ();
  GumFFIFunction * func = static_cast<GumFFIFunction *> (
      instance->GetPointerFromInternalField (0));

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

static Handle<Value>
gum_script_on_process_get_current_thread_id (const Arguments & args)
{
  (void) args;

  return Number::New (gum_process_get_current_thread_id ());
}

static Handle<Value>
gum_script_on_process_enumerate_threads (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> callbacks_value = args[0];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateThreads: argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_threads (gum_script_process_thread_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_process_thread_match (GumThreadDetails * details,
                                 gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Local<Object> thread (Object::New ());
  thread->Set (String::New ("id"), Number::New (details->id), ReadOnly);
  thread->Set (String::New ("state"),
      String::New (gum_script_thread_state_to_string (details->state)),
      ReadOnly);
  thread->Set (String::New ("registers"),
      gum_script_cpu_context_to_object (ctx->script, &details->cpu_context),
      ReadOnly);
  Handle<Value> argv[] = { thread };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static const gchar *
gum_script_thread_state_to_string (GumThreadState state)
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
  return NULL;
}

static Handle<Object>
gum_script_cpu_context_to_object (GumScript * self,
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
      _gum_script_pointer_new (self, GSIZE_TO_POINTER (pc)), ReadOnly);
  result->Set (String::New ("sp"),
      _gum_script_pointer_new (self, GSIZE_TO_POINTER (sp)), ReadOnly);

  return result;
}

static Handle<Value>
gum_script_on_process_enumerate_modules (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> callbacks_value = args[0];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateModules: argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_modules (gum_script_process_module_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_process_module_match (const gchar * name,
                                 const GumMemoryRange * range,
                                 const gchar * path,
                                 gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Handle<Value> argv[] = {
    String::New (name),
    _gum_script_pointer_new (ctx->script,
        GSIZE_TO_POINTER (range->base_address)),
    Integer::NewFromUnsigned (range->size),
    String::New (path)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 4, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_on_process_enumerate_ranges (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  GumPageProtection prot;
  if (!gum_script_page_protection_get (args[0], &prot))
    return Undefined ();

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateRanges: second argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_ranges (prot, gum_script_range_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_range_match (const GumMemoryRange * range,
                        GumPageProtection prot,
                        gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  char prot_str[4] = "---";
  if ((prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Handle<Value> argv[] = {
    _gum_script_pointer_new (ctx->script,
        GSIZE_TO_POINTER (range->base_address)),
    Integer::NewFromUnsigned (range->size),
    String::New (prot_str)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 3, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_on_thread_sleep (const Arguments & args)
{
  Local<Value> delay_val = args[0];
  if (!delay_val->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Thread.sleep: argument must be a number specifying delay")));
    return Undefined ();
  }
  double delay = delay_val->ToNumber ()->Value ();

  g_usleep (delay * G_USEC_PER_SEC);

  return Undefined ();
}

static Handle<Value>
gum_script_on_module_enumerate_exports (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> name_val = args[0];
  if (!name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateExports: first argument must be a string "
        "specifying a module name whose exports to enumerate")));
    return Undefined ();
  }
  String::Utf8Value name_str (name_val);

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateExports: second argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_module_enumerate_exports (*name_str, gum_script_module_export_match,
      &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_module_export_match (const gchar * name,
                                GumAddress address,
                                gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Handle<Value> argv[] = {
    String::New (name),
    _gum_script_pointer_new (ctx->script, GSIZE_TO_POINTER (address))
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 2, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_on_module_enumerate_ranges (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> name_val = args[0];
  if (!name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateRanges: first argument must be a string "
        "specifying a module name whose ranges to enumerate")));
    return Undefined ();
  }
  String::Utf8Value name_str (name_val);

  GumPageProtection prot;
  if (!gum_script_page_protection_get (args[1], &prot))
    return Undefined ();

  Local<Value> callbacks_value = args[2];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.enumerateRanges: third argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_module_enumerate_ranges (*name_str, prot, gum_script_range_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static Handle<Value>
gum_script_on_module_find_base_address (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> module_name_val = args[0];
  if (!module_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findBaseAddress: argument must be a string "
        "specifying module name")));
    return Undefined ();
  }
  String::Utf8Value module_name (module_name_val);

  GumAddress raw_address = gum_module_find_base_address (*module_name);
  if (raw_address == 0)
    return Null ();

  return _gum_script_pointer_new (self, GSIZE_TO_POINTER (raw_address));
}

static Handle<Value>
gum_script_on_module_find_export_by_name (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> module_name_val = args[0];
  if (!module_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findExportByName: first argument must be a string "
        "specifying module name")));
    return Undefined ();
  }
  String::Utf8Value module_name (module_name_val);

  Local<Value> symbol_name_val = args[1];
  if (!symbol_name_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Module.findExportByName: second argument must be a string "
        "specifying name of exported symbol")));
    return Undefined ();
  }
  String::Utf8Value symbol_name (symbol_name_val);

  GumAddress raw_address =
      gum_module_find_export_by_name (*module_name, *symbol_name);
  if (raw_address == 0)
    return Null ();

  return _gum_script_pointer_new (self, GSIZE_TO_POINTER (raw_address));
}

static Handle<Value>
gum_script_on_interceptor_attach (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  gpointer target;
  if (!_gum_script_pointer_get (self, args[0], &target))
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
  if (!gum_script_callbacks_get_opt (callbacks, "onEnter", &on_enter))
    return Undefined ();
  if (!gum_script_callbacks_get_opt (callbacks, "onLeave", &on_leave))
    return Undefined ();

  GumScriptAttachEntry * entry = g_slice_new (GumScriptAttachEntry);
  entry->on_enter = Persistent<Function>::New (on_enter);
  entry->on_leave = Persistent<Function>::New (on_leave);

  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      priv->interceptor, target, GUM_INVOCATION_LISTENER (self), entry);

  g_queue_push_tail (priv->attach_entries, entry);

  return (attach_ret == GUM_ATTACH_OK) ? True () : False ();
}

static void
gum_script_array_free (Persistent<Value> object,
                       void * data)
{
  int32_t length;

  HandleScope handle_scope;
  length = object->ToObject ()->Get (String::New ("length"))->Uint32Value ();
  V8::AdjustAmountOfExternalAllocatedMemory (-length);
  g_free (data);
  object.Dispose ();
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static Handle<Value>
gum_script_memory_do_read (const Arguments & args,
                           GumMemoryValueType type)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;
  Handle<Value> result;

  gpointer address;
  if (!_gum_script_pointer_get (self, args[0], &address))
    return Undefined ();

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_script_pointer_new (self, *static_cast<const gpointer *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (*static_cast<const gint8 *> (address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (*static_cast<const guint8 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (*static_cast<const gint16 *> (address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (*static_cast<const guint16 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (*static_cast<const gint32 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (*static_cast<const guint32 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = Number::New (*static_cast<const gint64 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = Number::New (*static_cast<const guint64 *> (
            address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = static_cast<const guint8 *> (address);
        if (data == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = args[1]->IntegerValue ();
        Handle<Object> array;
        if (length > 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          guint8 * buffer;

          memcpy (&dummy_to_trap_bad_pointer_early, data, 1);

          buffer = static_cast<guint8 *> (g_memdup (data, length));
          V8::AdjustAmountOfExternalAllocatedMemory (length);

          array = Object::New ();
          array->Set (String::New ("length"), Int32::New (length), ReadOnly);
          array->SetIndexedPropertiesToExternalArrayData (buffer,
              kExternalUnsignedByteArray, length);
          Persistent<Object> persistent_array = Persistent<Object>::New (array);
          persistent_array.MakeWeak (buffer, gum_script_array_free);
          persistent_array.MarkIndependent ();
        }
        else
        {
          array = Object::New ();
          length = 0;
        }
        array->Set (String::New ("length"), Int32::New (length), ReadOnly);

        result = array;
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const char * data = static_cast<const char *> (address);
        if (data == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = -1;
        if (args.Length () > 1)
          length = args[1]->IntegerValue();
        if (length < 0)
          length = g_utf8_strlen (data, -1);

        if (length != 0)
        {
          int size = g_utf8_offset_to_pointer (data, length) - data;
          result = String::New (data, size);
        }
        else
        {
          result = String::Empty ();
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        const gunichar2 * str_utf16 = static_cast<const gunichar2 *> (address);
        guint8 dummy_to_trap_bad_pointer_early;
        gchar * str_utf8;
        glong length, size;

        if (str_utf16 == NULL)
        {
          result = Null ();
          break;
        }

        memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, 1);

        length = (args.Length () > 1) ? args[1]->IntegerValue() : -1;
        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);

        length = size / sizeof (gunichar2);
        if (length != 0)
          result = String::New (str_utf8, size);
        else
          result = String::Empty ();

        break;
      }
#ifdef G_OS_WIN32
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
        const char * str_ansi = static_cast<const char *> (address);
        if (str_ansi == NULL)
        {
          result = Null ();
          break;
        }

        int64_t length = -1;
        if (args.Length () > 1)
          length = args[1]->IntegerValue();

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          gchar * str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          int size = g_utf8_offset_to_pointer (str_utf8,
              g_utf8_strlen (str_utf8, -1)) - str_utf8;
          result = String::New (str_utf8, size);
          g_free (str_utf8);
        }
        else
        {
          result = String::Empty ();
        }

        break;
      }
#endif
      default:
        g_assert_not_reached ();
    }
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  if (scope.exception_occurred)
  {
    gchar * message = g_strdup_printf (
        "access violation reading 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    ThrowException (Exception::Error (String::New (message)));
    g_free (message);

    result = Undefined ();
  }

  return result;
}

static Handle<Value>
gum_script_memory_do_write (const Arguments & args,
                            GumMemoryValueType type)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  gpointer address;
  if (!_gum_script_pointer_get (self, args[0], &address))
    return Undefined ();

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
      {
        gpointer value;
        if (_gum_script_pointer_get (self, args[1], &value))
          *static_cast<gpointer *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_U8:
      {
        guint8 value = args[1]->Uint32Value ();
        *static_cast<guint8 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        String::Utf8Value str (args[1]);
        strcpy (static_cast<char *> (address), *str);
        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  if (scope.exception_occurred)
  {
    gchar * message = g_strdup_printf (
        "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (scope.address));
    ThrowException (Exception::Error (String::New (message)));
    g_free (message);
  }

  return Undefined ();
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

#ifdef G_OS_WIN32

static void
gum_script_memory_do_longjmp (gum_jmp_buf * env)
{
  GUM_LONGJMP (*env, 1);
}

static gboolean
gum_script_memory_on_exception (EXCEPTION_RECORD * exception_record,
                                CONTEXT * context,
                                gpointer user_data)
{
  GumMemoryAccessScope * scope;

  (void) user_data;

  if (exception_record->ExceptionCode != STATUS_ACCESS_VIOLATION)
    return FALSE;

  /* must be a READ or WRITE */
  if (exception_record->ExceptionInformation[0] > 1)
    return FALSE;

  scope = (GumMemoryAccessScope *)
      GUM_TLS_KEY_GET_VALUE (gum_memaccess_scope_tls);
  if (scope == NULL)
    return FALSE;

  if (!scope->exception_occurred)
  {
    scope->exception_occurred = TRUE;

    scope->address = (gpointer) exception_record->ExceptionInformation[1];

#if GLIB_SIZEOF_VOID_P == 4
    context->Esp -= 8;
    *((gum_jmp_buf **) (context->Esp + 4)) = &scope->env;
    *((gum_jmp_buf **) (context->Esp + 0)) = NULL;
    context->Eip = (DWORD) gum_script_memory_do_longjmp;
#else
    context->Rsp -= 16;
    context->Rcx = (DWORD64) &scope->env;
    *((void **) (context->Rsp + 0)) = NULL;
    context->Rip = (DWORD64) gum_script_memory_do_longjmp;
#endif

    return TRUE;
  }

  return FALSE;
}

#else

static void
gum_script_memory_on_invalid_access (int sig,
                                     siginfo_t * siginfo,
                                     void * context)
{
  GumMemoryAccessScope * scope;
  struct sigaction * action;

  scope = (GumMemoryAccessScope *)
      GUM_TLS_KEY_GET_VALUE (gum_memaccess_scope_tls);
  if (scope == NULL)
    goto not_our_fault;

  if (!scope->exception_occurred)
  {
    scope->exception_occurred = TRUE;

    scope->address = siginfo->si_addr;
    GUM_LONGJMP (scope->env, 1);
  }

not_our_fault:
  action = &gum_memaccess_old_action;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (action->sa_sigaction != NULL)
      action->sa_sigaction (sig, siginfo, context);
    else
      abort ();
  }
  else
  {
    if (action->sa_handler != NULL)
      action->sa_handler (sig);
    else
      abort ();
  }
}

#endif

static Handle<Value>
gum_script_on_memory_scan (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  gpointer address;
  if (!_gum_script_pointer_get (self, args[0], &address))
    return Undefined ();
  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = args[1]->IntegerValue ();

  String::Utf8Value match_str (args[2]);

  Local<Value> callbacks_value = args[3];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New ("Memory.scan: "
        "fourth argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  Local<Function> on_match;
  if (!gum_script_callbacks_get (callbacks, "onMatch", &on_match))
    return Undefined ();
  Local<Function> on_error;
  if (!gum_script_callbacks_get_opt (callbacks, "onError", &on_error))
    return Undefined ();
  Local<Function> on_complete;
  if (!gum_script_callbacks_get (callbacks, "onComplete", &on_complete))
    return Undefined ();

  GumMatchPattern * pattern = gum_match_pattern_new_from_string (*match_str);
  if (pattern != NULL)
  {
    GumMemoryScanContext * ctx = g_slice_new (GumMemoryScanContext);

    ctx->script = self;
    g_object_ref (ctx->script);
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = Persistent<Function>::New (on_match);
    ctx->on_error = Persistent<Function>::New (on_error);
    ctx->on_complete = Persistent<Function>::New (on_complete);
    ctx->receiver = Persistent<Object>::New (args.This ());

    g_io_scheduler_push_job (gum_script_do_memory_scan, ctx,
        reinterpret_cast<GDestroyNotify> (gum_memory_scan_context_free),
        G_PRIORITY_DEFAULT, NULL);
  }
  else
  {
    ThrowException (Exception::Error (String::New ("invalid match pattern")));
  }

  return Undefined ();
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * ctx)
{
  if (ctx == NULL)
    return;

  gum_match_pattern_free (ctx->pattern);

  {
    Isolate * isolate = ctx->script->priv->isolate;
    Locker locker(isolate);
    Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope;
    ctx->on_match.Dispose ();
    ctx->on_error.Dispose ();
    ctx->on_complete.Dispose ();
    ctx->receiver.Dispose ();
  }

  g_object_unref (ctx->script);

  g_slice_free (GumMemoryScanContext, ctx);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static gboolean
gum_script_do_memory_scan (GIOSchedulerJob * job,
                           GCancellable * cancellable,
                           gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;

  (void) job;
  (void) cancellable;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    gum_memory_scan (&ctx->range, ctx->pattern, gum_script_process_scan_match,
        ctx);
  }

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, NULL);

  {
    ScriptScope script_scope (ctx->script);

    if (scope.exception_occurred && !ctx->on_error.IsEmpty ())
    {
      gchar * message = g_strdup_printf (
          "access violation reading 0x%" G_GSIZE_MODIFIER "x",
          GPOINTER_TO_SIZE (scope.address));
      Handle<Value> argv[] = { String::New (message) };
      ctx->on_error->Call (ctx->receiver, 1, argv);
      g_free (message);
    }

    ctx->on_complete->Call (ctx->receiver, 0, 0);
  }

  return FALSE;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

static gboolean
gum_script_process_scan_match (GumAddress address,
                               gsize size,
                               gpointer user_data)
{
  GumMemoryScanContext * ctx = static_cast<GumMemoryScanContext *> (user_data);
  ScriptScope scope (ctx->script);

  Handle<Value> argv[] = {
    _gum_script_pointer_new (ctx->script, GSIZE_TO_POINTER (address)),
    Integer::NewFromUnsigned (size)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 2, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_on_memory_alloc (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  uint32_t size = args[0]->Uint32Value ();
  if (size > 0x7fffffff)
  {
    ThrowException (Exception::TypeError (String::New ("invalid size")));
    return Undefined ();
  }

  gpointer block = g_malloc (size);
  Handle<Object> instance = _gum_script_pointer_new (self, block);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (block, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static void
gum_script_on_free_malloc_pointer (Persistent<Value> object,
                                   void * data)
{
  HandleScope handle_scope;
  g_free (data);
  object.Dispose ();
}

static Handle<Value>
gum_script_on_memory_read_pointer (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_POINTER);
}

static Handle<Value>
gum_script_on_memory_write_pointer (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_POINTER);
}

static Handle<Value>
gum_script_on_memory_read_s8 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S8);
}

static Handle<Value>
gum_script_on_memory_read_u8 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U8);
}

static Handle<Value>
gum_script_on_memory_write_u8 (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_U8);
}

static Handle<Value>
gum_script_on_memory_read_s16 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S16);
}

static Handle<Value>
gum_script_on_memory_read_u16 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U16);
}

static Handle<Value>
gum_script_on_memory_read_s32 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S32);
}

static Handle<Value>
gum_script_on_memory_read_u32 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U32);
}

static Handle<Value>
gum_script_on_memory_read_s64 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_S64);
}

static Handle<Value>
gum_script_on_memory_read_u64 (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_U64);
}

static Handle<Value>
gum_script_on_memory_read_byte_array (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_BYTE_ARRAY);
}

static Handle<Value>
gum_script_on_memory_read_utf8_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_UTF8_STRING);
}

static Handle<Value>
gum_script_on_memory_write_utf8_string (const Arguments & args)
{
  return gum_script_memory_do_write (args, GUM_MEMORY_VALUE_UTF8_STRING);
}

static Handle<Value>
gum_script_on_memory_read_utf16_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_UTF16_STRING);
}

#ifdef G_OS_WIN32

static Handle<Value>
gum_script_on_memory_read_ansi_string (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_ANSI_STRING);
}

static Handle<Value>
gum_script_on_memory_alloc_ansi_string (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gchar * str_heap = gum_ansi_string_from_utf8 (*str);
  Handle<Object> instance = _gum_script_pointer_new (self, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  guint str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_size = (guint) (length + 1) * sizeof (WCHAR);
  str_utf16 = (WCHAR *) g_malloc (str_utf16_size);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, length, str_utf16, str_utf16_size);
  str_utf16[length] = L'\0';
  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);
  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  gunichar2 * str_utf16;
  gchar * str_ansi;
  guint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  str_ansi_size = WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = (gchar *) g_malloc (str_ansi_size);
  WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);
  g_free (str_utf16);

  return str_ansi;
}

#endif

static Handle<Value>
gum_script_on_memory_alloc_utf8_string (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gchar * str_heap = g_strdup (*str);
  Handle<Object> instance = _gum_script_pointer_new (self, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static Handle<Value>
gum_script_on_memory_alloc_utf16_string (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gunichar2 * str_heap = g_utf8_to_utf16 (*str, -1, NULL, NULL, NULL);
  Handle<Object> instance = _gum_script_pointer_new (self, str_heap);

  Persistent<Object> persistent_instance = Persistent<Object>::New (instance);
  persistent_instance.MakeWeak (str_heap, gum_script_on_free_malloc_pointer);
  persistent_instance.MarkIndependent ();

  return instance;
}

static Handle<Value>
gum_script_on_socket_type (const Arguments & args)
{
  const gchar * result = NULL;

  int32_t socket = args[0]->ToInteger ()->Value ();

  int type;
  gum_socklen_t len = sizeof (int);
  if (getsockopt (socket, SOL_SOCKET, SO_TYPE, GUM_SOCKOPT_OPTVAL (&type),
      &len) == 0)
  {
    int family;

    struct sockaddr_in6 addr;
    len = sizeof (addr);
    if (getsockname (socket,
        reinterpret_cast<struct sockaddr *> (&addr), &len) == 0)
    {
      family = addr.sin6_family;
    }
    else
    {
      struct sockaddr_in invalid_sockaddr;
      invalid_sockaddr.sin_family = AF_INET;
      invalid_sockaddr.sin_port = htons (0);
      invalid_sockaddr.sin_addr.s_addr = htonl (0xffffffff);
      bind (socket,
          reinterpret_cast<struct sockaddr *> (&invalid_sockaddr),
          sizeof (invalid_sockaddr));
#ifdef G_OS_WIN32
      family = (WSAGetLastError () == WSAEADDRNOTAVAIL) ? AF_INET : AF_INET6;
#else
      family = (errno == EADDRNOTAVAIL) ? AF_INET : AF_INET6;
#endif
    }

    switch (family)
    {
      case AF_INET:
        switch (type)
        {
          case SOCK_STREAM: result = "tcp"; break;
          case  SOCK_DGRAM: result = "udp"; break;
        }
        break;
      case AF_INET6:
        switch (type)
        {
          case SOCK_STREAM: result = "tcp6"; break;
          case  SOCK_DGRAM: result = "udp6"; break;
        }
        break;
#ifndef G_OS_WIN32
      case AF_UNIX:
        switch (type)
        {
          case SOCK_STREAM: result = "unix:stream"; break;
          case  SOCK_DGRAM: result = "unix:dgram";  break;
        }
        break;
#endif
    }
  }

  return (result != NULL) ? String::New (result) : Null ();
}

static Handle<Value>
gum_script_on_socket_local_address (const Arguments & args)
{
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getsockname (args[0]->ToInteger ()->Value (), addr, &len) != 0)
    return Null ();
  return gum_script_socket_address_to_value (addr);
}

static Handle<Value>
gum_script_on_socket_peer_address (const Arguments & args)
{
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = reinterpret_cast<struct sockaddr *> (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getpeername (args[0]->ToInteger ()->Value (), addr, &len) != 0)
    return Null ();
  return gum_script_socket_address_to_value (addr);
}

static Handle<Value>
gum_script_socket_address_to_value (struct sockaddr * addr)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in * inet_addr =
          reinterpret_cast<struct sockaddr_in *> (addr);
#ifdef G_OS_WIN32
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = sizeof (ip);
      WSAAddressToStringA (addr, sizeof (struct sockaddr_in), NULL, ip, &len);
      gchar * p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];
      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New ());
      result->Set (String::New ("ip"), String::New (ip), ReadOnly);
      result->Set (String::New ("port"),
          Int32::New (ntohs (inet_addr->sin_port)), ReadOnly);
      return result;
    }
    case AF_INET6:
    {
      struct sockaddr_in6 * inet_addr =
          reinterpret_cast<struct sockaddr_in6 *> (addr);
#ifdef G_OS_WIN32
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = sizeof (ip);
      WSAAddressToStringA (addr, sizeof (struct sockaddr_in6), NULL, ip, &len);
      gchar * p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New ());
      result->Set (String::New ("ip"), String::New (ip), ReadOnly);
      result->Set (String::New ("port"),
          Int32::New (ntohs (inet_addr->sin6_port)), ReadOnly);
      return result;
    }
    case AF_UNIX:
    {
      Local<Object> result (Object::New ());
      result->Set (String::New ("path"), String::New ("") /* FIXME */,
          ReadOnly);
      return result;
    }
  }

  return Null ();
}

static Handle<Value>
gum_script_on_stalker_get_trust_threshold (Local<String> property,
                                           const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  GumStalker * stalker = gum_script_get_stalker (self);
  (void) property;
  return Number::New (gum_stalker_get_trust_threshold (stalker));
}

static void
gum_script_on_stalker_set_trust_threshold (Local<String> property,
                                           Local<Value> value,
                                           const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  GumStalker * stalker = gum_script_get_stalker (self);
  (void) property;
  gum_stalker_set_trust_threshold (stalker, value->IntegerValue ());
}

static Handle<Value>
gum_script_on_stalker_get_queue_capacity (Local<String> property,
                                          const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  (void) property;
  return Number::New (self->priv->stalker_queue_capacity);
}

static void
gum_script_on_stalker_set_queue_capacity (Local<String> property,
                                          Local<Value> value,
                                          const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  (void) property;
  self->priv->stalker_queue_capacity = value->IntegerValue ();
}

static Handle<Value>
gum_script_on_stalker_get_queue_drain_interval (Local<String> property,
                                                const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  (void) property;
  return Number::New (self->priv->stalker_queue_drain_interval);
}

static void
gum_script_on_stalker_set_queue_drain_interval (Local<String> property,
                                                Local<Value> value,
                                                const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  (void) property;
  self->priv->stalker_queue_drain_interval = value->IntegerValue ();
}

static Handle<Value>
gum_script_on_stalker_garbage_collect (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  gum_stalker_garbage_collect (gum_script_get_stalker (self));

  return Undefined ();
}

static Handle<Value>
gum_script_on_stalker_follow (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  GumThreadId thread_id;
  Local<Value> options_value;
  switch (args.Length ())
  {
    case 0:
      thread_id = gum_process_get_current_thread_id ();
      break;
    case 1:
      if (args[0]->IsNumber ())
      {
        thread_id = args[0]->IntegerValue ();
      }
      else
      {
        thread_id = gum_process_get_current_thread_id ();
        options_value = args[0];
      }
      break;
    default:
      thread_id = args[0]->IntegerValue ();
      options_value = args[1];
      break;
  }

  GumScriptEventSinkOptions so;
  so.script = self;
  so.main_context = priv->main_context;
  so.event_mask = GUM_NOTHING;
  so.queue_capacity = priv->stalker_queue_capacity;
  so.queue_drain_interval = priv->stalker_queue_drain_interval;

  if (!options_value.IsEmpty ())
  {
    if (!options_value->IsObject ())
    {
      ThrowException (Exception::TypeError (String::New ("Stalker.follow: "
          "options argument must be an object")));
      return Undefined ();
    }

    Local<Object> options = Local<Object>::Cast (options_value);

    Local<String> events_key (String::New ("events"));
    if (options->Has (events_key))
    {
      Local<Value> events_value (options->Get (events_key));
      if (!events_value->IsObject ())
      {
        ThrowException (Exception::TypeError (String::New ("Stalker.follow: "
            "events key must be an object")));
        return Undefined ();
      }

      Local<Object> events (Local<Object>::Cast (events_value));

      if (gum_script_flags_get (events, "call"))
        so.event_mask |= GUM_CALL;

      if (gum_script_flags_get (events, "ret"))
        so.event_mask |= GUM_RET;

      if (gum_script_flags_get (events, "exec"))
        so.event_mask |= GUM_EXEC;
    }

    if (so.event_mask != GUM_NOTHING &&
        !gum_script_callbacks_get_opt (options, "onReceive", &so.on_receive))
    {
      return Undefined ();
    }

    if ((so.event_mask & GUM_CALL) != 0)
    {
      gum_script_callbacks_get_opt (options, "onCallSummary",
          &so.on_call_summary);
    }
  }

  if (priv->stalker_sink != NULL)
  {
    g_object_unref (priv->stalker_sink);
    priv->stalker_sink = NULL;
  }

  priv->stalker_sink = gum_script_event_sink_new (&so);
  if (thread_id == gum_process_get_current_thread_id ())
  {
    priv->stalker_pending_follow_level = 1;
  }
  else
  {
    gum_stalker_follow (gum_script_get_stalker (self), thread_id,
        priv->stalker_sink);
    g_object_unref (priv->stalker_sink);
    priv->stalker_sink = NULL;
  }

  return Undefined ();
}

static Handle<Value>
gum_script_on_stalker_unfollow (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;
  GumStalker * stalker;
  GumThreadId thread_id;

  stalker = gum_script_get_stalker (self);

  if (args.Length () > 0)
    thread_id = args[0]->IntegerValue ();
  else
    thread_id = gum_process_get_current_thread_id ();

  if (thread_id == gum_process_get_current_thread_id ())
  {
    priv->stalker_pending_follow_level--;
  }
  else
  {
    gum_stalker_unfollow (stalker, thread_id);
  }

  return Undefined ();
}

static Handle<Value>
gum_script_on_stalker_add_call_probe (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptCallProbe * probe;
  GumProbeId id;

  gpointer target_address;
  if (!_gum_script_pointer_get (self, args[0], &target_address))
    return Undefined ();

  Local<Value> callback_value = args[1];
  if (!callback_value->IsFunction ())
  {
    ThrowException (Exception::TypeError (String::New ("Stalker.addCallProbe: "
        "second argument must be a function")));
    return Undefined ();
  }
  Local<Function> callback = Local<Function>::Cast (callback_value);

  probe = g_slice_new (GumScriptCallProbe);
  probe->script = self;
  probe->callback = Persistent<Function>::New (callback);
  probe->receiver = Persistent<Object>::New (args.This ());
  id = gum_stalker_add_call_probe (gum_script_get_stalker (self),
      target_address, gum_script_call_probe_fire,
      probe, reinterpret_cast<GDestroyNotify> (gum_script_call_probe_free));

  return Uint32::New (id);
}

static Handle<Value>
gum_script_on_stalker_remove_call_probe (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  Local<Value> id = args[0];
  if (!id->IsUint32 ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Stalker.removeCallProbe: argument must be a probe id")));
    return Undefined ();
  }

  gum_stalker_remove_call_probe (gum_script_get_stalker (self),
      id->ToUint32 ()->Value ());

  return Undefined ();
}

static void
gum_script_call_probe_free (GumScriptCallProbe * probe)
{
  Isolate * isolate = probe->script->priv->isolate;
  Locker locker(isolate);
  Isolate::Scope isolate_scope(isolate);
  HandleScope handle_scope;
  probe->callback.Dispose ();
  probe->receiver.Dispose ();
  g_slice_free (GumScriptCallProbe, probe);
}

static void
gum_script_call_probe_fire (GumCallSite * site,
                            gpointer user_data)
{
  GumScriptCallProbe * self = static_cast<GumScriptCallProbe *> (user_data);

  ScriptScope scope (self->script);
  Local<Object> args = self->script->priv->probe_args->NewInstance ();
  args->SetPointerInInternalField (0, self->script);
  args->SetPointerInInternalField (1, site);
  Handle<Value> argv[] = { args };
  self->callback->Call (self->receiver, 1, argv);
}

static Handle<Value>
gum_script_probe_args_on_get_nth (uint32_t index,
                                  const AccessorInfo & info)
{
  Handle<Object> instance = info.This ();
  GumScript * self = static_cast<GumScript *> (
      instance->GetPointerFromInternalField (0));
  GumCallSite * site = static_cast<GumCallSite *> (
      instance->GetPointerFromInternalField (1));
  gsize value;
  gsize * stack_argument = static_cast<gsize *> (site->stack_data);

#if GLIB_SIZEOF_VOID_P == 8
  switch (index)
  {
# if GUM_NATIVE_ABI_IS_UNIX
    case 0: value = site->cpu_context->rdi; break;
    case 1: value = site->cpu_context->rsi; break;
    case 2: value = site->cpu_context->rdx; break;
    case 3: value = site->cpu_context->rcx; break;
    case 4: value = site->cpu_context->r8;  break;
    case 5: value = site->cpu_context->r9;  break;
    default:
      value = stack_argument[index - 6];
      break;
# else
    case 0: value = site->cpu_context->rcx; break;
    case 1: value = site->cpu_context->rdx; break;
    case 2: value = site->cpu_context->r8;  break;
    case 3: value = site->cpu_context->r9;  break;
    default:
      value = stack_argument[index];
      break;
# endif
  }
#else
  value = stack_argument[index];
#endif

  return _gum_script_pointer_new (self, GSIZE_TO_POINTER (value));
}

static void
gum_script_on_enter (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  ScriptScope scope (self);

  Persistent<Object> receiver = Persistent<Object>::New (Object::New ());
  receiver->Set (String::New ("threadId"),
      Int32::New (gum_invocation_context_get_thread_id (context)),
      ReadOnly);
  receiver->Set (String::New ("depth"), Int32::New (*depth), ReadOnly);
  *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *) = *receiver;

  if (!entry->on_enter.IsEmpty ())
  {
    Local<Object> args = self->priv->invocation_args->NewInstance ();
    args->SetPointerInInternalField (0, context);

    Handle<Value> argv[] = { args };
    entry->on_enter->Call (receiver, 1, argv);
  }

  (*depth)++;
}

static void
gum_script_on_leave (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  (*depth)--;

  ScriptScope scope (self);

  Persistent<Object> receiver (
      *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *));

  if (!entry->on_leave.IsEmpty ())
  {
    gpointer raw_value = gum_invocation_context_get_return_value (context);
    Handle<Object> return_value (_gum_script_pointer_new (self, raw_value));

    Handle<Value> argv[] = { return_value };
    entry->on_leave->Call (receiver, 1, argv);
  }

  receiver.Dispose ();
}

static Handle<Value>
gum_script_invocation_args_on_get_nth (uint32_t index,
                                       const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));
  return _gum_script_pointer_new (self,
      gum_invocation_context_get_nth_argument (ctx, index));
}

static Handle<Value>
gum_script_invocation_args_on_set_nth (uint32_t index,
                                       Local<Value> value,
                                       const AccessorInfo & info)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (info.Data ()));
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));

  gpointer raw_value;
  if (!_gum_script_pointer_get (self, value, &raw_value))
    return Undefined ();

  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);

  return value;
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

  return FALSE;
}

static gboolean
gum_script_value_to_ffi_type (GumScript * self,
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
gum_script_value_from_ffi_type (GumScript * self,
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

static gboolean
gum_script_callbacks_get (Handle<Object> callbacks,
                          const gchar * name,
                          Handle<Function> * callback_function)
{
  if (!gum_script_callbacks_get_opt (callbacks, name, callback_function))
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

static gboolean
gum_script_callbacks_get_opt (Handle<Object> callbacks,
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

static gboolean
gum_script_flags_get (Handle<Object> flags,
                      const gchar * name)
{
  Local<String> key (String::New (name));
  return flags->Has (key) && flags->Get (key)->ToBoolean ()->BooleanValue ();
}

static gboolean
gum_script_page_protection_get (Handle<Value> prot_val,
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

Handle<Object>
_gum_script_pointer_new (GumScript * self,
                         gpointer address)
{
  Local<Object> native_pointer_object =
      self->priv->native_pointer_value->Clone ();
  native_pointer_object->SetPointerInInternalField (0, address);
  return native_pointer_object;
}

gboolean
_gum_script_pointer_get (GumScript * self,
                         Handle<Value> value,
                         gpointer * target)
{
  if (!self->priv->native_pointer->HasInstance (value))
  {
    ThrowException (Exception::TypeError (String::New (
        "expected NativePointer object")));
    return FALSE;
  }
  *target = value->ToObject ()->GetPointerFromInternalField (0);

  return TRUE;
}
