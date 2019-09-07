/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukscript.h"

#include "gumdukapiresolver.h"
#include "gumdukcmodule.h"
#include "gumdukcoderelocator.h"
#include "gumdukcodewriter.h"
#include "gumdukcore.h"
#include "gumdukdatabase.h"
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
#include <string.h>

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

struct _GumDukScript
{
  GObject parent;

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
  GumDukModule module;
  GumDukProcess process;
  GumDukThread thread;
  GumDukFile file;
  GumDukStream stream;
  GumDukSocket socket;
  GumDukDatabase database;
  GumDukInterceptor interceptor;
  GumDukApiResolver api_resolver;
  GumDukSymbol symbol;
  GumDukCModule cmodule;
  GumDukInstruction instruction;
  GumDukCodeWriter code_writer;
  GumDukCodeRelocator code_relocator;
  GumDukStalker stalker;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;

  GumDukScriptDebugger debugger;
};

enum
{
  DEBUGGER_DETACHED,
  DEBUGGER_OUTPUT,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_BYTECODE,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
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

static gboolean gum_duk_script_try_rename_from_filename (GumDukScript * self,
    const gchar * filename);

G_DEFINE_TYPE_EXTENDED (GumDukScript,
                        gum_duk_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_duk_script_iface_init))

static guint gum_duk_script_signals[LAST_SIGNAL] = { 0, };

static void
gum_duk_script_class_init (GumDukScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_script_dispose;
  object_class->finalize = gum_duk_script_finalize;
  object_class->get_property = gum_duk_script_get_property;
  object_class->set_property = gum_duk_script_set_property;

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

  gum_duk_script_signals[DEBUGGER_DETACHED] =
      g_signal_new ("debugger-detached", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_VOID__VOID,
      G_TYPE_NONE, 0);
  gum_duk_script_signals[DEBUGGER_OUTPUT] =
      g_signal_new ("debugger-output", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_VOID__BOXED,
      G_TYPE_NONE, 1, G_TYPE_BYTES);
}

static void
gum_duk_script_iface_init (gpointer g_iface,
                           gpointer iface_data)
{
  GumScriptInterface * iface = g_iface;

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
  self->name = g_strdup ("agent");

  self->state = GUM_SCRIPT_STATE_UNLOADED;
  self->on_unload = NULL;

  gum_duk_script_debugger_init (&self->debugger, self);
}

static void
gum_duk_script_dispose (GObject * object)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);
  GumScript * script = GUM_SCRIPT (self);

  gum_duk_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_duk_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_duk_script_parent_class)->dispose (object);
}

static void
gum_duk_script_finalize (GObject * object)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);

  gum_duk_script_debugger_finalize (&self->debugger);

  g_free (self->name);
  g_free (self->source);
  g_bytes_unref (self->bytecode);

  G_OBJECT_CLASS (gum_duk_script_parent_class)->finalize (object);
}

static void
gum_duk_script_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumDukScript * self = GUM_DUK_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, self->source);
      break;
    case PROP_BYTECODE:
      g_value_set_boxed (value, self->bytecode);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, self->main_context);
      break;
    case PROP_BACKEND:
      g_value_set_object (value, self->backend);
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

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_SOURCE:
      g_free (self->source);
      self->source = g_value_dup_string (value);
      break;
    case PROP_BYTECODE:
      g_bytes_unref (self->bytecode);
      self->bytecode = g_value_dup_boxed (value);
      break;
    case PROP_MAIN_CONTEXT:
      if (self->main_context != NULL)
        g_main_context_unref (self->main_context);
      self->main_context = g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (self->backend != NULL)
        g_object_unref (self->backend);
      self->backend = GUM_DUK_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_duk_script_create_context (GumDukScript * self,
                               GError ** error)
{
  GumDukCore * core = &self->core;
  duk_context * ctx;
  GumDukScope scope = { core, NULL, };

  g_assert (self->ctx == NULL);

  ctx = gum_duk_script_backend_create_heap (self->backend);

  if (self->bytecode != NULL)
  {
    gconstpointer code;
    gsize size;

    duk_push_external_buffer (ctx);

    code = g_bytes_get_data (self->bytecode, &size);
    duk_config_buffer (ctx, -1, (void *) code, size);

    duk_load_function (ctx);

    duk_get_prop_string (ctx, -1, "fileName");
    if (duk_is_string (ctx, -1))
    {
      gum_duk_script_try_rename_from_filename (self,
          duk_require_string (ctx, -1));
    }
    duk_pop (ctx);
  }
  else
  {
    if (!gum_duk_script_backend_push_program (self->backend, ctx, self->name,
        self->source, error))
    {
      duk_destroy_heap (ctx);

      return FALSE;
    }
  }

  /* pop the function */
  self->code = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  self->ctx = ctx;

  _gum_duk_core_init (core, self,
      gum_duk_script_backend_get_scope_mutex (self->backend),
      gumjs_frida_source_map, &self->interceptor, &self->stalker,
      gum_duk_script_emit, gum_duk_script_backend_get_scheduler (self->backend),
      self->ctx);

  scope.ctx = self->ctx;
  core->current_scope = &scope;

  _gum_duk_kernel_init (&self->kernel, core);
  _gum_duk_memory_init (&self->memory, core);
  _gum_duk_module_init (&self->module, core);
  _gum_duk_process_init (&self->process, &self->module, core);
  _gum_duk_thread_init (&self->thread, core);
  _gum_duk_file_init (&self->file, core);
  _gum_duk_stream_init (&self->stream, core);
  _gum_duk_socket_init (&self->socket, core);
  _gum_duk_database_init (&self->database, core);
  _gum_duk_interceptor_init (&self->interceptor, core);
  _gum_duk_api_resolver_init (&self->api_resolver, core);
  _gum_duk_symbol_init (&self->symbol, core);
  _gum_duk_cmodule_init (&self->cmodule, core);
  _gum_duk_instruction_init (&self->instruction, core);
  _gum_duk_code_writer_init (&self->code_writer, core);
  _gum_duk_code_relocator_init (&self->code_relocator, &self->code_writer,
      &self->instruction, core);
  _gum_duk_stalker_init (&self->stalker, &self->code_writer, &self->instruction,
      core);

  core->current_scope = NULL;

  return TRUE;
}

static void
gum_duk_script_destroy_context (GumDukScript * self)
{
  GumDukCore * core = &self->core;

  g_assert (self->ctx != NULL);

  {
    GumDukScope scope;

    _gum_duk_scope_enter (&scope, core);

    _gum_duk_stalker_dispose (&self->stalker);
    _gum_duk_code_relocator_dispose (&self->code_relocator);
    _gum_duk_code_writer_dispose (&self->code_writer);
    _gum_duk_instruction_dispose (&self->instruction);
    _gum_duk_cmodule_dispose (&self->cmodule);
    _gum_duk_symbol_dispose (&self->symbol);
    _gum_duk_api_resolver_dispose (&self->api_resolver);
    _gum_duk_interceptor_dispose (&self->interceptor);
    _gum_duk_database_dispose (&self->database);
    _gum_duk_socket_dispose (&self->socket);
    _gum_duk_stream_dispose (&self->stream);
    _gum_duk_file_dispose (&self->file);
    _gum_duk_thread_dispose (&self->thread);
    _gum_duk_process_dispose (&self->process);
    _gum_duk_module_dispose (&self->module);
    _gum_duk_memory_dispose (&self->memory);
    _gum_duk_kernel_dispose (&self->kernel);
    _gum_duk_core_dispose (core);

    _gum_duk_scope_leave (&scope);
  }

  {
    GumDukScope scope = { core, NULL, };

    scope.ctx = self->ctx;
    core->current_scope = &scope;

    _gum_duk_release_heapptr (self->ctx, self->code);
    self->code = NULL;

    duk_destroy_heap (self->ctx);
    self->ctx = NULL;

    core->current_scope = NULL;
  }

  _gum_duk_stalker_finalize (&self->stalker);
  _gum_duk_code_relocator_finalize (&self->code_relocator);
  _gum_duk_code_writer_finalize (&self->code_writer);
  _gum_duk_instruction_finalize (&self->instruction);
  _gum_duk_cmodule_finalize (&self->cmodule);
  _gum_duk_symbol_finalize (&self->symbol);
  _gum_duk_api_resolver_finalize (&self->api_resolver);
  _gum_duk_interceptor_finalize (&self->interceptor);
  _gum_duk_database_finalize (&self->database);
  _gum_duk_socket_finalize (&self->socket);
  _gum_duk_stream_finalize (&self->stream);
  _gum_duk_file_finalize (&self->file);
  _gum_duk_thread_finalize (&self->thread);
  _gum_duk_process_finalize (&self->process);
  _gum_duk_module_finalize (&self->module);
  _gum_duk_memory_finalize (&self->memory);
  _gum_duk_kernel_finalize (&self->kernel);
  _gum_duk_core_finalize (core);
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
      gum_duk_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_duk_script_load_finish (GumScript * script,
                            GAsyncResult * result)
{
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
      gum_duk_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_duk_script_do_load (GumScriptTask * task,
                        GumDukScript * self,
                        gpointer task_data,
                        GCancellable * cancellable)
{
  switch (self->state)
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
  if (self->state == GUM_SCRIPT_STATE_UNLOADED)
  {
    GumDukScope scope;
    duk_context * ctx;

    if (self->ctx == NULL)
    {
      gum_duk_script_create_context (self, NULL);
    }

    ctx = _gum_duk_scope_enter (&scope, &self->core);

    gum_duk_bundle_load (gumjs_runtime_modules, ctx);

    duk_push_heapptr (ctx, self->code);
    _gum_duk_scope_call (&scope, 0);
    duk_pop (ctx);

    _gum_duk_scope_leave (&scope);

    self->state = GUM_SCRIPT_STATE_LOADED;
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
      gum_duk_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_duk_script_unload_finish (GumScript * script,
                              GAsyncResult * result)
{
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
      gum_duk_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_duk_script_do_unload (GumScriptTask * task,
                          GumDukScript * self,
                          gpointer task_data,
                          GCancellable * cancellable)
{
  switch (self->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
      gum_duk_script_complete_unload_task (self, task);
      break;
    case GUM_SCRIPT_STATE_LOADED:
      self->state = GUM_SCRIPT_STATE_UNLOADING;
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
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_duk_script_try_unload (GumDukScript * self)
{
  GumDukScope scope;
  gboolean success;

  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  _gum_duk_scope_enter (&scope, &self->core);

  _gum_duk_stalker_flush (&self->stalker);
  _gum_duk_interceptor_flush (&self->interceptor);
  _gum_duk_socket_flush (&self->socket);
  _gum_duk_stream_flush (&self->stream);
  _gum_duk_process_flush (&self->process);
  success = _gum_duk_core_flush (&self->core, gum_duk_script_try_unload);

  _gum_duk_scope_leave (&scope);

  if (success)
  {
    gum_duk_script_destroy_context (self);

    self->state = GUM_SCRIPT_STATE_UNLOADED;

    while (self->on_unload != NULL)
    {
      GSList * link = self->on_unload;
      GumUnloadNotifyCallback * callback = link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      self->on_unload = g_slist_delete_link (self->on_unload, link);
    }
  }
}

static void
gum_duk_script_once_unloaded (GumDukScript * self,
                              GumUnloadNotifyFunc func,
                              gpointer data,
                              GDestroyNotify data_destroy)
{
  GumUnloadNotifyCallback * callback;

  callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  self->on_unload = g_slist_append (self->on_unload, callback);
}

static void
gum_duk_script_set_message_handler (GumScript * script,
                                    GumScriptMessageHandler handler,
                                    gpointer data,
                                    GDestroyNotify data_destroy)
{
  GumDukScript * self = GUM_DUK_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
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
      gum_duk_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_post, d,
      (GDestroyNotify) gum_duk_post_data_free);
}

static void
gum_duk_script_do_post (GumPostData * d)
{
  GBytes * data;

  data = d->data;
  d->data = NULL;

  _gum_duk_core_post (&d->script->core, d->message, data);
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

  return _gum_duk_stalker_get (&self->stalker);
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
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_duk_script_do_emit (GumEmitData * d)
{
  GumDukScript * self = d->script;

  if (self->message_handler != NULL)
  {
    self->message_handler (GUM_SCRIPT (self), d->message, d->data,
        self->message_handler_data);
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
      gum_duk_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_attach_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_do_attach_debugger (GumDukScript * self)
{
  GumDukScope scope;

  if (self->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &self->core);

  gum_duk_script_debugger_attach (&self->debugger);

  _gum_duk_scope_leave (&scope);
}

void
gum_duk_script_detach_debugger (GumDukScript * self)
{
  gum_duk_script_debugger_cancel (&self->debugger);

  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_do_detach_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_do_detach_debugger (GumDukScript * self)
{
  GumDukScope scope;

  if (self->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &self->core);

  gum_duk_script_debugger_detach (&self->debugger);

  _gum_duk_scope_leave (&scope);
}

void
gum_duk_script_post_to_debugger (GumDukScript * self,
                                 GBytes * bytes)
{
  gboolean delivered;

  delivered = gum_duk_script_debugger_try_post (&self->debugger, bytes);
  if (!delivered)
    return;

  gum_script_scheduler_push_job_on_js_thread (
      gum_duk_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_duk_script_awaken_debugger,
      g_object_ref (self), g_object_unref);
}

static void
gum_duk_script_awaken_debugger (GumDukScript * self)
{
  GumDukScope scope;

  if (self->ctx == NULL)
    return;

  _gum_duk_scope_enter (&scope, &self->core);

  gum_duk_script_debugger_process_pending (&self->debugger);

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

  duk_debugger_attach (self->script->core.heap_ctx,
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

  duk_debugger_detach (self->script->core.heap_ctx);
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
  duk_debugger_cooperate (self->script->core.heap_ctx);
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

  g_signal_emit (self->script, gum_duk_script_signals[DEBUGGER_OUTPUT], 0,
      unwritten);

  g_bytes_unref (unwritten);
}

static void
gum_duk_script_debugger_on_detached (duk_context * ctx,
                                     GumDukScriptDebugger * self)
{
  GUM_DUK_SCRIPT_DEBUGGER_LOCK (self);

  self->attached = FALSE;
  g_clear_pointer (&self->unread, g_byte_array_unref);
  self->unread_offset = 0;

  GUM_DUK_SCRIPT_DEBUGGER_UNLOCK (self);

  g_signal_emit (self->script, gum_duk_script_signals[DEBUGGER_DETACHED], 0);
}

static gboolean
gum_duk_script_try_rename_from_filename (GumDukScript * self,
                                         const gchar * filename)
{
  gboolean success = FALSE;
  gchar * basename, * extension;

  basename = g_path_get_basename (filename);

  extension = strrchr (basename, '.');
  if (extension != NULL)
    *extension = '\0';

  if (strlen (basename) > 0)
  {
    g_free (self->name);
    self->name = g_steal_pointer (&basename);

    success = TRUE;
  }

  g_free (basename);

  return success;
}

void
_gum_duk_panic (duk_context * ctx,
                const char * error_message)
{
  /* TODO: need to find a way to retrieve the stack */
  g_critical ("%s", error_message);

  abort ();
}
