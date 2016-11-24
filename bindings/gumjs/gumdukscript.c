/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukscript.h"

#include "gumdukapiresolver.h"
#include "gumdukcore.h"
#include "gumdukfile.h"
#include "gumdukinstruction.h"
#include "gumdukinterceptor.h"
#include "gumdukkernel.h"
#include "gumdukmemory.h"
#include "gumdukmodule.h"
#include "gumdukprocess.h"
#include "gumdukscript-runtime.h"
#include "gumduksocket.h"
#include "gumdukstalker.h"
#include "gumdukstream.h"
#include "gumduksymbol.h"
#include "gumdukthread.h"
#include "gumdukvalue.h"
#include "gumscripttask.h"

#include <gum/guminvocationlistener.h>

#define GUM_DUK_SCRIPT_DEBUGGER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_DUK_SCRIPT_DEBUGGER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

#define GUM_DUK_SCRIPT_DEBUGGER_WAIT(o) g_cond_wait (&(o)->cond, &(o)->mutex)
#define GUM_DUK_SCRIPT_DEBUGGER_SIGNAL(o) g_cond_signal (&(o)->cond)

typedef guint GumScriptState;
typedef struct _GumDukScriptDebugger GumDukScriptDebugger;
typedef struct _GumUnloadNotifyCallback GumUnloadNotifyCallback;
typedef void (* GumUnloadNotifyFunc) (GumDukScript * self, gpointer user_data);
typedef struct _GumEmitData GumEmitData;
typedef struct _GumPostData GumPostData;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_BYTECODE,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

enum
{
  SIGNAL_DEBUGGER_DETACHED,
  SIGNAL_DEBUGGER_OUTPUT,

  LAST_SIGNAL
};

struct _GumDukScriptDebugger
{
  GMutex mutex;
  GCond cond;

  volatile gboolean attached;
  volatile gboolean cancelled;

  GByteArray * unread;
  duk_size_t unread_offset;
  GByteArray * unwritten;

  GumDukScript * script;
};

struct _GumDukScriptPrivate
{
  gchar * name;
  gchar * source;
  GBytes * bytecode;
  GMainContext * main_context;
  GumDukScriptBackend * backend;

  GumScriptState state;
  GSList * on_unload;
  duk_context * ctx;
  GumDukHeapPtr code;
  GumDukCore core;
  GumDukKernel kernel;
  GumDukMemory memory;
  GumDukProcess process;
  GumDukThread thread;
  GumDukModule module;
  GumDukFile file;
  GumDukStream stream;
  GumDukSocket socket;
  GumDukInterceptor interceptor;
  GumDukStalker stalker;
  GumDukApiResolver api_resolver;
  GumDukSymbol symbol;
  GumDukInstruction instruction;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;

  GumDukScriptDebugger debugger;
};

enum _GumScriptState
{
  GUM_SCRIPT_STATE_UNLOADED = 1,
  GUM_SCRIPT_STATE_LOADED,
  GUM_SCRIPT_STATE_UNLOADING
};

struct _GumUnloadNotifyCallback
{
  GumUnloadNotifyFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct _GumEmitData
{
  GumDukScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumPostData
{
  GumDukScript * script;
  gchar * message;
  GBytes * data;
};

static void gum_duk_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_duk_script_dispose (GObject * object);
static void gum_duk_script_finalize (GObject * object);
static void gum_duk_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_duk_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_duk_script_destroy_context (GumDukScript * self);

static void gum_duk_script_load (GumScript * script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_duk_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_duk_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_duk_script_do_load (GumScriptTask * task, GumDukScript * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_duk_script_perform_load_task (GumDukScript * self,
    GumScriptTask * task);
static void gum_duk_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_duk_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_duk_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_duk_script_do_unload (GumScriptTask * task, GumDukScript * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_duk_script_complete_unload_task (GumDukScript * self,
    GumScriptTask * task);
static void gum_duk_script_try_unload (GumDukScript * self);
static void gum_duk_script_once_unloaded (GumDukScript * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_duk_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_duk_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_duk_script_do_post (GumPostData * d);
static void gum_duk_post_data_free (GumPostData * d);

static GumStalker * gum_duk_script_get_stalker (GumScript * script);

static void gum_duk_script_emit (GumDukScript * self,
    const gchar * message, GBytes * data);
static gboolean gum_duk_script_do_emit (GumEmitData * d);
static void gum_duk_emit_data_free (GumEmitData * d);

static void gum_duk_script_do_attach_debugger (GumDukScript * self);
static void gum_duk_script_do_detach_debugger (GumDukScript * self);
static void gum_duk_script_awaken_debugger (GumDukScript * self);

static void gum_duk_script_debugger_init (GumDukScriptDebugger * self,
    GumDukScript * script);
static void gum_duk_script_debugger_finalize (GumDukScriptDebugger * self);
static void gum_duk_script_debugger_attach (GumDukScriptDebugger * self);
static void gum_duk_script_debugger_detach (GumDukScriptDebugger * self);
static void gum_duk_script_debugger_cancel (GumDukScriptDebugger * self);
static gboolean gum_duk_script_debugger_try_post (GumDukScriptDebugger * self,
    GBytes * bytes);
static void gum_duk_script_debugger_process_pending (
    GumDukScriptDebugger * self);
static duk_size_t gum_duk_script_debugger_on_read (GumDukScriptDebugger * self,
    char * buffer, duk_size_t length);
static duk_size_t gum_duk_script_debugger_on_write (GumDukScriptDebugger * self,
    const char * buffer, duk_size_t length);
static duk_size_t gum_duk_script_debugger_on_peek (GumDukScriptDebugger * self);
static void gum_duk_script_debugger_on_write_flush (
    GumDukScriptDebugger * self);
static void gum_duk_script_debugger_on_detached (duk_context * ctx,
    GumDukScriptDebugger * self);

G_DEFINE_TYPE_EXTENDED (GumDukScript,
                        gum_duk_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_duk_script_iface_init));

static guint gum_duk_script_signals[LAST_SIGNAL] = { 0, };

static void
gum_duk_script_class_init (GumDukScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumDukScriptPrivate));

  object_class->dispose = gum_duk_script_dispose;
  object_class->finalize = gum_duk_script_finalize;
  object_class->get_property = gum_duk_script_get_property;
  object_class->set_property = gum_duk_script_set_property;

  klass->debugger_detached = NULL;
  klass->debugger_output = NULL;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BYTECODE,
      g_param_spec_boxed ("bytecode", "Bytecode", "Bytecode", G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_DUK_TYPE_SCRIPT_BACKEND,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  gum_duk_script_signals[SIGNAL_DEBUGGER_DETACHED] =
      g_signal_new ("debugger-detached", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GumDukScriptClass, debugger_detached),
      NULL, NULL, g_cclosure_marshal_VOID__VOID, G_TYPE_NONE, 0);
  gum_duk_script_signals[SIGNAL_DEBUGGER_OUTPUT] =
      g_signal_new ("debugger-output", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GumDukScriptClass, debugger_output),
      NULL, NULL, g_cclosure_marshal_VOID__BOXED, G_TYPE_NONE, 1,
      G_TYPE_BYTES);
}

static void
gum_duk_script_iface_init (gpointer g_iface,
                           gpointer iface_data)
{
  GumScriptIface * iface = (GumScriptIface *) g_iface;

  (void) iface_data;

  iface->load = gum_duk_script_load;
  iface->load_finish = gum_duk_script_load_finish;
  iface->load_sync = gum_duk_script_load_sync;
  iface->unload = gum_duk_script_unload;
  iface->unload_finish = gum_duk_script_unload_finish;
  iface->unload_sync = gum_duk_script_unload_sync;

  iface->set_message_handler = gum_duk_script_set_message_handler;
  iface->post = gum_duk_script_post;

  iface->get_stalker = gum_duk_script_get_stalker;
}

static void
gum_duk_script_init (GumDukScript * self)
{
  GumDukScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_DUK_TYPE_SCRIPT, GumDukScriptPrivate);

  priv->state = GUM_SCRIPT_STATE_UNLOADED;
  priv->on_unload = NULL;

  gum_duk_script_debugger_init (&priv->debugger, self);
}

static void
gum_duk_script_dispose (GObject * object)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);
  GumDukScriptPrivate * priv = self->priv;
  GumScript * script = GUM_SCRIPT (self);

  gum_duk_script_set_message_handler (script, NULL, NULL, NULL);

  if (priv->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_duk_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    g_clear_pointer (&priv->main_context, g_main_context_unref);
    g_clear_pointer (&priv->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_duk_script_parent_class)->dispose (object);
}

static void
gum_duk_script_finalize (GObject * object)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);
  GumDukScriptPrivate * priv = self->priv;

  gum_duk_script_debugger_finalize (&priv->debugger);

  g_free (priv->name);
  g_free (priv->source);
  g_bytes_unref (priv->bytecode);

  G_OBJECT_CLASS (gum_duk_script_parent_class)->finalize (object);
}

static void
gum_duk_script_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);
  GumDukScriptPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, priv->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, priv->source);
      break;
    case PROP_BYTECODE:
      g_value_set_boxed (value, priv->bytecode);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, priv->main_context);
      break;
    case PROP_BACKEND:
      g_value_set_object (value, priv->backend);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_duk_script_set_property (GObject * object,
                             guint property_id,
                             const GValue * value,
                             GParamSpec * pspec)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);
  GumDukScriptPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_free (priv->name);
      priv->name = g_value_dup_string (value);
      break;
    case PROP_SOURCE:
      g_free (priv->source);
      priv->source = g_value_dup_string (value);
      break;
    case PROP_BYTECODE:
      g_bytes_unref (priv->bytecode);
      priv->bytecode = g_value_dup_boxed (value);
      break;
    case PROP_MAIN_CONTEXT:
      if (priv->main_context != NULL)
        g_main_context_unref (priv->main_context);
      priv->main_context = g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (priv->backend != NULL)
        g_object_unref (priv->backend);
      priv->backend = GUM_DUK_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_duk_script_create_context (GumDukScript * self,
                               GError ** error)
{
  GumDukScriptPrivate * priv = self->priv;
  duk_context * ctx;

  g_assert (priv->ctx == NULL);

  ctx = gum_duk_script_backend_create_heap (priv->backend);

  if (priv->bytecode != NULL)
  {
    gconstpointer code;
    gsize size;
    gchar * url;

    duk_push_external_buffer (ctx);

    code = g_bytes_get_data (priv->bytecode, &size);
    duk_config_buffer (ctx, -1, (void *) code, size);

    duk_load_function (ctx);

    url = g_strconcat (priv->name, ".js", NULL);
    duk_push_string (ctx, url);
    duk_put_prop_string (ctx, -2, "fileName");
    g_free (url);
  }
  else
  {
    if (!gum_duk_script_backend_push_program (priv->backend, ctx, priv->name,
        priv->source, error))
    {
      duk_destroy_heap (ctx);

      return FALSE;
    }
  }

  /* pop the function */
  priv->code = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  priv->ctx = ctx;

  _gum_duk_core_init (&priv->core, self, gumjs_frida_source_map,
      &priv->interceptor, gum_duk_script_emit,
      gum_duk_script_backend_get_scheduler (priv->backend), priv->ctx);

  priv->core.current_ctx = priv->core.heap_ctx;

  _gum_duk_kernel_init (&priv->kernel, &priv->core);
  _gum_duk_memory_init (&priv->memory, &priv->core);
  _gum_duk_process_init (&priv->process, &priv->core);
  _gum_duk_thread_init (&priv->thread, &priv->core);
  _gum_duk_module_init (&priv->module, &priv->core);
  _gum_duk_file_init (&priv->file, &priv->core);
  _gum_duk_stream_init (&priv->stream, &priv->core);
  _gum_duk_socket_init (&priv->socket, &priv->core);
  _gum_duk_interceptor_init (&priv->interceptor, &priv->core);
  _gum_duk_stalker_init (&priv->stalker, &priv->core);
  _gum_duk_api_resolver_init (&priv->api_resolver, &priv->core);
  _gum_duk_symbol_init (&priv->symbol, &priv->core);
  _gum_duk_instruction_init (&priv->instruction, &priv->core);

  priv->core.current_ctx = NULL;

  return TRUE;
}

static void
gum_duk_script_destroy_context (GumDukScript * self)
{
  GumDukScriptPrivate * priv = self->priv;
  GumDukScope scope;

  g_assert (priv->ctx != NULL);

  _gum_duk_scope_enter (&scope, &priv->core);

  _gum_duk_instruction_dispose (&priv->instruction);
  _gum_duk_symbol_dispose (&priv->symbol);
  _gum_duk_api_resolver_dispose (&priv->api_resolver);
  _gum_duk_stalker_dispose (&priv->stalker);
  _gum_duk_interceptor_dispose (&priv->interceptor);
  _gum_duk_socket_dispose (&priv->socket);
  _gum_duk_stream_dispose (&priv->stream);
  _gum_duk_file_dispose (&priv->file);
  _gum_duk_module_dispose (&priv->module);
  _gum_duk_thread_dispose (&priv->thread);
  _gum_duk_process_dispose (&priv->process);
  _gum_duk_memory_dispose (&priv->memory);
  _gum_duk_kernel_dispose (&priv->kernel);
  _gum_duk_core_dispose (&priv->core);

  _gum_duk_scope_leave (&scope);

  _gum_duk_release_heapptr (priv->ctx, priv->code);
  priv->code = NULL;

  duk_destroy_heap (priv->ctx);
  priv->ctx = NULL;

  _gum_duk_instruction_finalize (&priv->instruction);
  _gum_duk_symbol_finalize (&priv->symbol);
  _gum_duk_api_resolver_finalize (&priv->api_resolver);
  _gum_duk_stalker_finalize (&priv->stalker);
  _gum_duk_interceptor_finalize (&priv->interceptor);
  _gum_duk_socket_finalize (&priv->socket);
  _gum_duk_stream_finalize (&priv->stream);
  _gum_duk_file_finalize (&priv->file);
  _gum_duk_module_finalize (&priv->module);
  _gum_duk_thread_finalize (&priv->thread);
  _gum_duk_process_finalize (&priv->process);
  _gum_duk_memory_finalize (&priv->memory);
  _gum_duk_kernel_finalize (&priv->kernel);
  _gum_duk_core_finalize (&priv->core);
}

static void
gum_duk_script_load (GumScript * script,
                     GCancellable * cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_duk_script_do_load, self,
      cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_duk_script_load_finish (GumScript * script,
                            GAsyncResult * result)
{
  (void) script;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_duk_script_load_sync (GumScript * script,
                          GCancellable * cancellable)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_duk_script_do_load, self,
      cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_duk_script_do_load (GumScriptTask * task,
                        GumDukScript * self,
                        gpointer task_data,
                        GCancellable * cancellable)
{
  (void) task_data;
  (void) cancellable;

  switch (self->priv->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
    case GUM_SCRIPT_STATE_LOADED:
      gum_duk_script_perform_load_task (self, task);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_duk_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_duk_script_perform_load_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_duk_script_perform_load_task (GumDukScript * self,
                                  GumScriptTask * task)
{
  GumDukScriptPrivate * priv = self->priv;

  if (priv->state == GUM_SCRIPT_STATE_UNLOADED)
  {
    GumDukScope scope;
    duk_context * ctx;

    if (priv->ctx == NULL)
    {
      gboolean created;

      created = gum_duk_script_create_context (self, NULL);
      g_assert (created);
    }

    ctx = _gum_duk_scope_enter (&scope, &priv->core);

    gum_duk_bundle_load (gumjs_runtime_modules, ctx);

    duk_push_heapptr (ctx, priv->code);
    _gum_duk_scope_call (&scope, 0);
    duk_pop (ctx);

    _gum_duk_scope_leave (&scope);

    priv->state = GUM_SCRIPT_STATE_LOADED;
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_duk_script_unload (GumScript * script,
                       GCancellable * cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_duk_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_duk_script_unload_finish (GumScript * script,
                              GAsyncResult * result)
{
  (void) script;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_duk_script_unload_sync (GumScript * script,
                            GCancellable * cancellable)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_duk_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_duk_script_do_unload (GumScriptTask * task,
                          GumDukScript * self,
                          gpointer task_data,
                          GCancellable * cancellable)
{
  GumDukScriptPrivate * priv = self->priv;

  (void) task_data;
  (void) cancellable;

  switch (priv->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
      gum_duk_script_complete_unload_task (self, task);
      break;
    case GUM_SCRIPT_STATE_LOADED:
      priv->state = GUM_SCRIPT_STATE_UNLOADING;
      gum_duk_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_duk_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      gum_duk_script_try_unload (self);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_duk_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_duk_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_duk_script_complete_unload_task (GumDukScript * self,
                                     GumScriptTask * task)
{
  (void) self;

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_duk_script_try_unload (GumDukScript * self)
{
  GumDukScriptPrivate * priv = self->priv;
  GumDukScope scope;
  gboolean success;

  g_assert_cmpuint (priv->state, ==, GUM_SCRIPT_STATE_UNLOADING);

  _gum_duk_scope_enter (&scope, &priv->core);

  _gum_duk_stalker_flush (&priv->stalker);
  _gum_duk_interceptor_flush (&priv->interceptor);
  _gum_duk_socket_flush (&priv->socket);
  _gum_duk_stream_flush (&priv->stream);
  _gum_duk_process_flush (&priv->process);
  success = _gum_duk_core_flush (&priv->core, gum_duk_script_try_unload);

  _gum_duk_scope_leave (&scope);

  if (success)
  {
    gum_duk_script_destroy_context (self);

    priv->state = GUM_SCRIPT_STATE_UNLOADED;

    while (priv->on_unload != NULL)
    {
      GSList * link = priv->on_unload;
      GumUnloadNotifyCallback * callback = link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      priv->on_unload = g_slist_delete_link (priv->on_unload, link);
    }
  }
}

static void
gum_duk_script_once_unloaded (GumDukScript * self,
                              GumUnloadNotifyFunc func,
                              gpointer data,
                              GDestroyNotify data_destroy)
{
  GumDukScriptPrivate * priv = self->priv;
  GumUnloadNotifyCallback * callback;

  callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  priv->on_unload = g_slist_append (priv->on_unload, callback);
}

static void
gum_duk_script_set_message_handler (GumScript * script,
                                    GumScriptMessageHandler handler,
                                    gpointer data,
                                    GDestroyNotify data_destroy)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumDukScriptPrivate * priv = self->priv;

  if (priv->message_handler_data_destroy != NULL)
    priv->message_handler_data_destroy (priv->message_handler_data);
  priv->message_handler = handler;
  priv->message_handler_data = data;
  priv->message_handler_data_destroy = data_destroy;
}

static void
gum_duk_script_post (GumScript * script,
                     const gchar * message,
                     GBytes * data)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);
  GumPostData * d;

  d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_post, d,
      (GDestroyNotify) gum_duk_post_data_free);
}

static void
gum_duk_script_do_post (GumPostData * d)
{
  GBytes * data;

  data = d->data;
  d->data = NULL;

  _gum_duk_core_post (&d->script->priv->core, d->message, data);
}

static void
gum_duk_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static GumStalker *
gum_duk_script_get_stalker (GumScript * script)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);

  return _gum_duk_stalker_get (&self->priv->stalker);
}

static void
gum_duk_script_emit (GumDukScript * self,
                     const gchar * message,
                     GBytes * data)
{
  GumEmitData * d;
  GSource * source;

  d = g_slice_new (GumEmitData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_duk_script_do_emit,
      d,
      (GDestroyNotify) gum_duk_emit_data_free);
  g_source_attach (source, self->priv->main_context);
  g_source_unref (source);
}

static gboolean
gum_duk_script_do_emit (GumEmitData * d)
{
  GumDukScript * self = d->script;
  GumDukScriptPrivate * priv = self->priv;

  if (priv->message_handler != NULL)
  {
    priv->message_handler (GUM_SCRIPT (self), d->message, d->data,
        priv->message_handler_data);
  }

  return FALSE;
}

static void
gum_duk_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}

void
gum_duk_script_attach_debugger (GumDukScript * self)
{
  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_attach_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_do_attach_debugger (GumDukScript * self)
{
  GumDukScriptPrivate * priv = self->priv;
  GumDukScope scope;

  if (priv->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &priv->core);

  gum_duk_script_debugger_attach (&priv->debugger);

  _gum_duk_scope_leave (&scope);
}

void
gum_duk_script_detach_debugger (GumDukScript * self)
{
  gum_duk_script_debugger_cancel (&self->priv->debugger);

  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_detach_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_do_detach_debugger (GumDukScript * self)
{
  GumDukScriptPrivate * priv = self->priv;
  GumDukScope scope;

  if (priv->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &priv->core);

  gum_duk_script_debugger_detach (&priv->debugger);

  _gum_duk_scope_leave (&scope);
}

void
gum_duk_script_post_to_debugger (GumDukScript * self,
                                 GBytes * bytes)
{
  gboolean delivered;

  delivered = gum_duk_script_debugger_try_post (&self->priv->debugger, bytes);
  if (!delivered)
    return;

  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_awaken_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_awaken_debugger (GumDukScript * self)
{
  GumDukScriptPrivate * priv = self->priv;
  GumDukScope scope;

  if (priv->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &priv->core);

  gum_duk_script_debugger_process_pending (&priv->debugger);

  _gum_duk_scope_leave (&scope);
}

static void
gum_duk_script_debugger_init (GumDukScriptDebugger * self,
                              GumDukScript * script)
{
  g_mutex_init (&self->mutex);
  g_cond_init (&self->cond);

  self->attached = FALSE;
  self->cancelled = FALSE;

  self->unread = NULL;
  self->unread_offset = 0;
  self->unwritten = g_byte_array_new ();

  self->script = script;
}

static void
gum_duk_script_debugger_finalize (GumDukScriptDebugger * self)
{
  g_clear_pointer (&self->unwritten, g_byte_array_unref);
  g_clear_pointer (&self->unread, g_byte_array_unref);

  g_cond_clear (&self->cond);
  g_mutex_clear (&self->mutex);
}

static void
gum_duk_script_debugger_attach (GumDukScriptDebugger * self)
{
  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  if (self->attached)
  {
    GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);
    return;
  }

  self->attached = TRUE;
  self->cancelled = FALSE;

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  duk_debugger_attach (self->script->priv->core.heap_ctx,
      (duk_debug_read_function) gum_duk_script_debugger_on_read,
      (duk_debug_write_function) gum_duk_script_debugger_on_write,
      (duk_debug_peek_function) gum_duk_script_debugger_on_peek,
      (duk_debug_read_flush_function) NULL,
      (duk_debug_write_flush_function) gum_duk_script_debugger_on_write_flush,
      (duk_debug_request_function) NULL,
      (duk_debug_detached_function) gum_duk_script_debugger_on_detached,
      self);
}

static void
gum_duk_script_debugger_detach (GumDukScriptDebugger * self)
{
  gboolean attached;

  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);
  attached = self->attached;
  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  if (!attached)
    return;

  duk_debugger_detach (self->script->priv->core.heap_ctx);
}

static void
gum_duk_script_debugger_cancel (GumDukScriptDebugger * self)
{
  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);
  self->cancelled = TRUE;
  GUM_DUK_SCRIPT_DEBUGGER_SIGNAL (self);
  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);
}

static gboolean
gum_duk_script_debugger_try_post (GumDukScriptDebugger * self,
                                  GBytes * bytes)
{
  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  if (!self->attached)
  {
    GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

    g_bytes_unref (bytes);

    return FALSE;
  }

  if (self->unread == NULL)
  {
    self->unread = g_bytes_unref_to_array (bytes);
  }
  else
  {
    gpointer data;
    gsize size;

    data = g_bytes_unref_to_data (bytes, &size);
    g_byte_array_append (self->unread, data, size);
    g_free (data);
  }

  GUM_DUK_SCRIPT_DEBUGGER_SIGNAL (self);
  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  return TRUE;
}

static void
gum_duk_script_debugger_process_pending (GumDukScriptDebugger * self)
{
  duk_debugger_cooperate (self->script->priv->core.heap_ctx);
}

static duk_size_t
gum_duk_script_debugger_on_read (GumDukScriptDebugger * self,
                                 char * buffer,
                                 duk_size_t length)
{
  duk_size_t n = 0, available = 0;

  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  while ((self->unread == NULL ||
      (available = self->unread->len - self->unread_offset) == 0) &&
      !self->cancelled)
  {
    GUM_DUK_SCRIPT_DEBUGGER_WAIT (self);
  }

  if (available > 0)
  {
    n = MIN (length, available);
    memcpy (buffer, self->unread->data + self->unread_offset, n);

    self->unread_offset += n;

    if (self->unread_offset == self->unread->len)
    {
      g_byte_array_unref (self->unread);
      self->unread = NULL;
      self->unread_offset = 0;
    }
    else if (self->unread_offset > 2048)
    {
      g_byte_array_remove_range (self->unread, 0, (guint) self->unread_offset);
      self->unread_offset = 0;
    }
  }

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  return n;
}

static duk_size_t
gum_duk_script_debugger_on_write (GumDukScriptDebugger * self,
                                  const char * buffer,
                                  duk_size_t length)
{
  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);
  g_byte_array_append (self->unwritten, (const guint8 *) buffer,
      (guint) length);
  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  return length;
}

static duk_size_t
gum_duk_script_debugger_on_peek (GumDukScriptDebugger * self)
{
  duk_size_t available;

  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  available = (self->unread != NULL)
      ? self->unread->len - self->unread_offset
      : 0;

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  return available;
}

static void
gum_duk_script_debugger_on_write_flush (GumDukScriptDebugger * self)
{
  GBytes * unwritten = NULL;

  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  if (self->unwritten->len > 0)
  {
    unwritten = g_byte_array_free_to_bytes (self->unwritten);
    self->unwritten = g_byte_array_new ();
  }

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  if (unwritten == NULL)
    return;

  g_signal_emit (self->script, gum_duk_script_signals[SIGNAL_DEBUGGER_OUTPUT],
      0, unwritten);

  g_bytes_unref (unwritten);
}

static void
gum_duk_script_debugger_on_detached (duk_context * ctx,
                                     GumDukScriptDebugger * self)
{
  (void) ctx;

  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  self->attached = FALSE;
  g_clear_pointer (&self->unread, g_byte_array_unref);
  self->unread_offset = 0;

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  g_signal_emit (self->script, gum_duk_script_signals[SIGNAL_DEBUGGER_DETACHED],
      0);
}

void
_gum_duk_panic (duk_context * ctx,
                const char * error_message)
{
  (void) ctx;

  /* TODO: need to find a way to retrieve the stack */
  g_critical ("%s", error_message);

  abort ();
}
