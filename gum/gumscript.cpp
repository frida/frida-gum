/*
 * Copyright (C) 2010-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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
#include "gumscriptscope.h"
#include "gumstalker.h"
#include "gumtls.h"
#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#endif

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

struct _GumScriptPrivate
{
  GMainContext * main_context;

  GumInterceptor * interceptor;
  GumStalker * stalker;

  Persistent<Context> context;
  Persistent<Script> raw_script;
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
  GQueue * heap_blocks;
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
  GUM_MEMORY_VALUE_SWORD,
  GUM_MEMORY_VALUE_UWORD,
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
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

struct _GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  Persistent<Function> on_match;
  Persistent<Function> on_error;
  Persistent<Function> on_complete;
  Persistent<Object> receiver;

  GumScript * script;
};

struct _GumScriptCallProbe
{
  GumScript * script;
  Persistent<Function> callback;
  Persistent<Object> receiver;
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
static Handle<Object> gum_script_cpu_context_to_object (
    const GumCpuContext * ctx);
static Handle<Value> gum_script_on_process_enumerate_modules (
    const Arguments & args);
static gboolean gum_script_process_module_match (const gchar * name,
    GumAddress address, const gchar * path, gpointer user_data);
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
static Handle<Value> gum_script_on_int32_cast (const Arguments & args);
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

static Handle<Value> gum_script_on_memory_read_sword (const Arguments & args);
static Handle<Value> gum_script_on_memory_read_uword (const Arguments & args);
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

static gboolean gum_script_callbacks_get (Handle<Object> callbacks,
    const gchar * name, Local<Function> * callback_function);
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

  priv->mutex = g_mutex_new ();

  priv->event_cond = g_cond_new ();

  priv->attach_entries = g_queue_new ();
  priv->heap_blocks = g_queue_new ();

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
    Locker l;
    HandleScope handle_scope;
    Context::Scope context_scope (priv->context);

    gum_script_unload (self);

    priv->main_context = NULL;

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

    while (!g_queue_is_empty (priv->heap_blocks))
      g_free (g_queue_pop_tail (priv->heap_blocks));

    priv->invocation_args.Dispose ();
    priv->invocation_args.Clear ();
    priv->probe_args.Dispose ();
    priv->probe_args.Clear ();
    priv->raw_script.Dispose ();
    priv->raw_script.Clear ();
    priv->context.Dispose ();
    priv->context.Clear ();
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
  g_queue_free (priv->heap_blocks);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

static void
gum_script_create_context (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;
  Locker l;
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
      FunctionTemplate::New (gum_script_on_process_enumerate_threads));
  process_templ->Set (String::New ("enumerateModules"),
      FunctionTemplate::New (gum_script_on_process_enumerate_modules));
  process_templ->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_on_process_enumerate_ranges));
  global_templ->Set (String::New ("Process"), process_templ);

  Handle<ObjectTemplate> thread_templ = ObjectTemplate::New ();
  thread_templ->Set (String::New ("sleep"),
      FunctionTemplate::New (gum_script_on_thread_sleep));
  global_templ->Set (String::New ("Thread"), thread_templ);

  Handle<ObjectTemplate> module_templ = ObjectTemplate::New ();
  module_templ->Set (String::New ("enumerateExports"),
      FunctionTemplate::New (gum_script_on_module_enumerate_exports));
  module_templ->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_on_module_enumerate_ranges));
  module_templ->Set (String::New ("findBaseAddress"),
      FunctionTemplate::New (gum_script_on_module_find_base_address));
  module_templ->Set (String::New ("findExportByName"),
      FunctionTemplate::New (gum_script_on_module_find_export_by_name));
  global_templ->Set (String::New ("Module"), module_templ);

  global_templ->Set (String::New ("Int32"),
      FunctionTemplate::New (gum_script_on_int32_cast, External::Wrap (self)));

  Handle<ObjectTemplate> memory_templ = ObjectTemplate::New ();
  memory_templ->Set (String::New ("scan"),
      FunctionTemplate::New (gum_script_on_memory_scan,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readSWord"),
      FunctionTemplate::New (gum_script_on_memory_read_sword,
          External::Wrap (self)));
  memory_templ->Set (String::New ("readUWord"),
      FunctionTemplate::New (gum_script_on_memory_read_uword,
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
    Handle<ObjectTemplate> args_templ = ObjectTemplate::New ();
    args_templ->SetInternalFieldCount (1);
    args_templ->SetIndexedPropertyHandler (
        gum_script_invocation_args_on_get_nth,
        gum_script_invocation_args_on_set_nth);
    priv->invocation_args = Persistent<ObjectTemplate>::New (args_templ);
  }

  {
    Handle<ObjectTemplate> args_templ = ObjectTemplate::New ();
    args_templ->SetInternalFieldCount (1);
    args_templ->SetIndexedPropertyHandler (gum_script_probe_args_on_get_nth);
    priv->probe_args = Persistent<ObjectTemplate>::New (args_templ);
  }
}

ScriptScope::ScriptScope (GumScript * parent)
  : parent (parent),
    context_scope (parent->priv->context)
{
}

ScriptScope::~ScriptScope ()
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

GumScript *
gum_script_from_string (const gchar * source,
                        GError ** error)
{
  GumScript * script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));

  Locker l;
  HandleScope handle_scope;
  Context::Scope context_scope (script->priv->context);

  gchar * combined_source = g_strconcat (gum_script_runtime_source, "\n",
      source, NULL);
  Handle<String> source_value = String::New (combined_source);
  g_free (combined_source);
  TryCatch trycatch;
  Handle<Script> raw_script = Script::Compile (source_value);
  if (raw_script.IsEmpty ())
  {
    g_object_unref (script);

    Handle<Message> message = trycatch.Message ();
    Handle<Value> exception = trycatch.Exception ();
    String::AsciiValue exception_str (exception);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Script(line %d): %s",
        message->GetLineNumber () - GUM_SCRIPT_RUNTIME_SOURCE_LINE_COUNT,
        *exception_str);

    return NULL;
  }

  script->priv->raw_script = Persistent<Script>::New (raw_script);

  return script;
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
  Locker l;
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
    Unlocker ul;

    g_mutex_lock (priv->mutex);
    g_cond_wait (priv->event_cond, priv->mutex);
    g_mutex_unlock (priv->mutex);
  }

  return Undefined ();
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
      gum_script_cpu_context_to_object (&details->cpu_context),
      ReadOnly);
  Handle<Value> argv[] = { thread };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (result->IsString ())
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
gum_script_cpu_context_to_object (const GumCpuContext * ctx)
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

  result->Set (String::New ("pc"), Number::New (pc), ReadOnly);
  result->Set (String::New ("sp"), Number::New (sp), ReadOnly);

  return result;
}

static Handle<Value>
gum_script_on_process_enumerate_modules (const Arguments & args)
{
  GumScriptMatchContext ctx;

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
                                 GumAddress address,
                                 const gchar * path,
                                 gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Handle<Value> argv[] = {
    String::New (name),
    Number::New (address),
    String::New (path)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 3, argv);

  gboolean proceed = TRUE;
  if (result->IsString ())
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
    Number::New (range->base_address),
    Integer::NewFromUnsigned (range->size),
    String::New (prot_str)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 3, argv);

  gboolean proceed = TRUE;
  if (result->IsString ())
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
    Number::New (address)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 2, argv);

  gboolean proceed = TRUE;
  if (result->IsString ())
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

  return Number::New (raw_address);
}

static Handle<Value>
gum_script_on_module_find_export_by_name (const Arguments & args)
{
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

  return Number::New (raw_address);
}

static Handle<Value>
gum_script_on_interceptor_attach (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  Local<Value> target_spec = args[0];
  if (!target_spec->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New ("Interceptor.attach: "
        "first argument must be a memory address")));
    return Undefined ();
  }

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New ("Interceptor.attach: "
        "second argument must be a callback object")));
    return Undefined ();
  }

  Local<Function> on_enter, on_leave;

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onEnter", &on_enter))
    return Undefined ();
  if (!gum_script_callbacks_get (callbacks, "onLeave", &on_leave))
    return Undefined ();

  GumScriptAttachEntry * entry = g_slice_new (GumScriptAttachEntry);
  entry->on_enter = Persistent<Function>::New (on_enter);
  entry->on_leave = Persistent<Function>::New (on_leave);

  gpointer function_address = GSIZE_TO_POINTER (target_spec->IntegerValue ());
  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      priv->interceptor, function_address, GUM_INVOCATION_LISTENER (self),
      entry);

  g_queue_push_tail (priv->attach_entries, entry);

  return (attach_ret == GUM_ATTACH_OK) ? True () : False ();
}

static Handle<Value>
gum_script_on_int32_cast (const Arguments & args)
{
  return Number::New (args[0]->Int32Value ());
}

static void
gum_script_array_free (Persistent<Value> object, void * data)
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
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;
  Handle<Value> address = args[0];
  Handle<Value> result;

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_SWORD:
        result = Integer::New (*static_cast<const int *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_UWORD:
        result = Integer::New (*static_cast<const unsigned int *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (*static_cast<const gint8 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (*static_cast<const guint8 *> (
            GSIZE_TO_POINTER (address->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (*static_cast<const gint16 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (*static_cast<const guint16 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (*static_cast<const gint32 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (*static_cast<const guint32 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = Number::New (*static_cast<const gint64 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_U64:
        result = Number::New (*static_cast<const guint64 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ())));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = static_cast<const guint8 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ()));
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
        const char * data = static_cast<const char *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ()));
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
        const gunichar2 * str_utf16 = static_cast<const gunichar2 *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ()));
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
        const char * str_ansi = static_cast<const char *> (
            GSIZE_TO_POINTER (args[0]->IntegerValue ()));
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
  GumMemoryAccessScope scope = GUM_MEMORY_ACCESS_SCOPE_INIT;
  gpointer address = GSIZE_TO_POINTER (args[1]->IntegerValue ());

  GUM_TLS_KEY_SET_VALUE (gum_memaccess_scope_tls, &scope);

  if (GUM_SETJMP (scope.env) == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_U8:
      {
        guint8 value = args[0]->Uint32Value ();
        *static_cast<guint8 *> (address) = value;
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        String::Utf8Value str (args[0]);
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
  GumMemoryRange range;
  range.base_address = args[0]->IntegerValue ();
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
  if (!gum_script_callbacks_get (callbacks, "onError", &on_error))
    return Undefined ();
  Local<Function> on_complete;
  if (!gum_script_callbacks_get (callbacks, "onComplete", &on_complete))
    return Undefined ();

  GumMatchPattern * pattern = gum_match_pattern_new_from_string (*match_str);
  if (pattern != NULL)
  {
    GumMemoryScanContext * ctx = g_slice_new (GumMemoryScanContext);
    ctx->range = range;
    ctx->pattern = pattern;
    ctx->on_match = Persistent<Function>::New (on_match);
    ctx->on_error = Persistent<Function>::New (on_error);
    ctx->on_complete = Persistent<Function>::New (on_complete);
    ctx->receiver = Persistent<Object>::New (args.This ());

    ctx->script = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
    g_object_ref (ctx->script);

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
    Locker l;
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

    if (scope.exception_occurred)
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
    Number::New (address),
    Integer::NewFromUnsigned (size)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 2, argv);

  gboolean proceed = TRUE;
  if (result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_on_memory_read_sword (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_SWORD);
}

static Handle<Value>
gum_script_on_memory_read_uword (const Arguments & args)
{
  return gum_script_memory_do_read (args, GUM_MEMORY_VALUE_UWORD);
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
  g_queue_push_tail (self->priv->heap_blocks, str_heap);

  return Number::New (GPOINTER_TO_SIZE (str_heap));
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
  g_queue_push_tail (self->priv->heap_blocks, str_heap);

  return Number::New (GPOINTER_TO_SIZE (str_heap));
}

static Handle<Value>
gum_script_on_memory_alloc_utf16_string (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));

  String::Utf8Value str (args[0]);
  gunichar2 * str_heap = g_utf8_to_utf16 (*str, -1, NULL, NULL, NULL);
  g_queue_push_tail (self->priv->heap_blocks, str_heap);

  return Number::New (GPOINTER_TO_SIZE (str_heap));
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
gum_script_on_stalker_follow (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  GumThreadId thread_id;
  Local<Value> callbacks_value;
  if (args[0]->IsNumber ())
  {
    thread_id = args[0]->IntegerValue ();
    callbacks_value = args[1];
  }
  else
  {
    thread_id = gum_process_get_current_thread_id ();
    callbacks_value = args[0];
  }

  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New ("Stalker.follow: "
        "argument must be a callback object")));
    return Undefined ();
  }

  Local<Function> on_receive;

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!gum_script_callbacks_get (callbacks, "onReceive", &on_receive))
    return Undefined ();

  if (priv->stalker == NULL)
    priv->stalker = gum_stalker_new ();
  GumEventSink * sink = gum_script_event_sink_new (self, priv->main_context, on_receive);
  gum_stalker_follow (priv->stalker, thread_id, sink);
  g_object_unref (sink);

  return Undefined ();
}

static Handle<Value>
gum_script_on_stalker_unfollow (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  if (priv->stalker == NULL)
    return False ();

  if (args.Length () > 0)
  {
    GumThreadId thread_id = args[0]->IntegerValue ();
    gum_stalker_unfollow (priv->stalker, thread_id);
  }
  else
  {
    if (!gum_stalker_is_following_me (priv->stalker))
      return False ();
    gum_stalker_unfollow_me (priv->stalker);
  }

  return True ();
}

static Handle<Value>
gum_script_on_stalker_add_call_probe (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;
  GumScriptCallProbe * probe;
  GumProbeId id;

  Local<Value> target_spec = args[0];
  if (!target_spec->IsNumber ())
  {
    ThrowException (Exception::TypeError (String::New ("Stalker.addCallProbe: "
        "first argument must be a memory address")));
    return Undefined ();
  }
  gpointer target_address = GSIZE_TO_POINTER (target_spec->IntegerValue ());

  Local<Value> callback_value = args[1];
  if (!callback_value->IsFunction ())
  {
    ThrowException (Exception::TypeError (String::New ("Stalker.addCallProbe: "
        "second argument must be a function")));
    return Undefined ();
  }
  Local<Function> callback = Local<Function>::Cast (callback_value);

  if (priv->stalker == NULL)
    priv->stalker = gum_stalker_new ();

  probe = g_slice_new (GumScriptCallProbe);
  probe->script = self;
  probe->callback = Persistent<Function>::New (callback);
  probe->receiver = Persistent<Object>::New (args.This ());
  id = gum_stalker_add_call_probe (priv->stalker, target_address,
      gum_script_call_probe_fire,
      probe, reinterpret_cast<GDestroyNotify> (gum_script_call_probe_free));

  return Uint32::New (id);
}

static Handle<Value>
gum_script_on_stalker_remove_call_probe (const Arguments & args)
{
  GumScript * self = GUM_SCRIPT_CAST (External::Unwrap (args.Data ()));
  GumScriptPrivate * priv = self->priv;

  Local<Value> id = args[0];
  if (!id->IsUint32 ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Stalker.removeCallProbe: argument must be a probe id")));
    return Undefined ();
  }

  if (priv->stalker == NULL)
    return Undefined ();

  gum_stalker_remove_call_probe (priv->stalker, id->ToUint32 ()->Value ());

  return Undefined ();
}

static void
gum_script_call_probe_free (GumScriptCallProbe * probe)
{
  Locker l;
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
  args->SetPointerInInternalField (0, site);
  Handle<Value> argv[] = { args };
  self->callback->Call (self->receiver, 1, argv);
}

static Handle<Value>
gum_script_probe_args_on_get_nth (uint32_t index,
                                  const AccessorInfo & info)
{
  GumCallSite * site = static_cast<GumCallSite *> (
      info.This ()->GetPointerFromInternalField (0));
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
# else
    case 0: value = site->cpu_context->rcx; break;
    case 1: value = site->cpu_context->rdx; break;
    case 2: value = site->cpu_context->r8;  break;
    case 3: value = site->cpu_context->r9;  break;
# endif
    default:
      value = stack_argument[index];
      break;
  }
#else
  value = stack_argument[index];
#endif

  return Number::New (value);
}

static void
gum_script_on_enter (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));

  ScriptScope scope (self);

  Persistent<Object> receiver = Persistent<Object>::New (Object::New ());
  receiver->Set (String::New ("threadId"),
      Int32::New (gum_invocation_context_get_thread_id (context)),
      ReadOnly);
  *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *) = *receiver;

  if (!entry->on_enter.IsEmpty ())
  {
    Local<Object> args = self->priv->invocation_args->NewInstance ();
    args->SetPointerInInternalField (0, context);

    Handle<Value> argv[] = { args };
    entry->on_enter->Call (receiver, 1, argv);
  }
}

static void
gum_script_on_leave (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);
  GumScriptAttachEntry * entry = static_cast<GumScriptAttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));

  ScriptScope scope (self);

  Persistent<Object> receiver (
      *GUM_LINCTX_GET_FUNC_INVDATA (context, Object *));

  if (!entry->on_leave.IsEmpty ())
  {
    gpointer raw_value = gum_invocation_context_get_return_value (context);
    Local<Number> return_value (Number::New (GPOINTER_TO_SIZE (raw_value)));

    Handle<Value> argv[] = { return_value };
    entry->on_leave->Call (receiver, 1, argv);
  }

  receiver.Dispose ();
}

static Handle<Value>
gum_script_invocation_args_on_get_nth (uint32_t index,
                                       const AccessorInfo & info)
{
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));

  gpointer raw_value = gum_invocation_context_get_nth_argument (ctx, index);

  return Number::New (GPOINTER_TO_SIZE (raw_value));
}

static Handle<Value>
gum_script_invocation_args_on_set_nth (uint32_t index,
                                       Local<Value> value,
                                       const AccessorInfo & info)
{
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.This ()->GetPointerFromInternalField (0));

  if (!value->IsNumber ())
  {
    ThrowException (Exception::TypeError (
        String::New ("can only assign a number")));
    return Undefined ();
  }

  gpointer raw_value = GSIZE_TO_POINTER (value->IntegerValue ());
  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);

  return value;
}

static gboolean
gum_script_callbacks_get (Handle<Object> callbacks,
                          const gchar * name,
                          Local<Function> * callback_function)
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
