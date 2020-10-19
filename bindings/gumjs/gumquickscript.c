/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickscript.h"

#if 0
#include "gumquickapiresolver.h"
#include "gumquickcmodule.h"
#include "gumquickcoderelocator.h"
#include "gumquickcodewriter.h"
#endif
#include "gumquickcore.h"
#if 0
#include "gumquickdatabase.h"
#include "gumquickfile.h"
#include "gumquickinstruction.h"
#endif
#include "gumquickinterceptor.h"
#if 0
#include "gumquickkernel.h"
#include "gumquickmemory.h"
#include "gumquickmodule.h"
#include "gumquickprocess.h"
#endif
#include "gumquickscript-priv.h"
#include "gumquickscript-runtime.h"
#include "gumquickscriptbackend.h"
#if 0
#include "gumquicksocket.h"
#endif
#include "gumquickstalker.h"
#if 0
#include "gumquickstream.h"
#include "gumquicksymbol.h"
#include "gumquickthread.h"
#include "gumquickvalue.h"
#endif
#include "gumscripttask.h"

typedef guint GumScriptState;
typedef struct _GumUnloadNotifyCallback GumUnloadNotifyCallback;
typedef void (* GumUnloadNotifyFunc) (GumQuickScript * self, gpointer user_data);
typedef struct _GumEmitData GumEmitData;
typedef struct _GumPostData GumPostData;

struct _GumQuickScript
{
  GObject parent;

  gchar * name;
  gchar * source;
  GBytes * bytecode;
  GMainContext * main_context;
  GumQuickScriptBackend * backend;

  GumScriptState state;
  GSList * on_unload;
  JSRuntime * rt;
  JSContext * ctx;
  JSValue code;
  GumQuickCore core;
#if 0
  GumQuickKernel kernel;
  GumQuickMemory memory;
  GumQuickModule module;
  GumQuickProcess process;
  GumQuickThread thread;
  GumQuickFile file;
  GumQuickStream stream;
  GumQuickSocket socket;
  GumQuickDatabase database;
#endif
  GumQuickInterceptor interceptor;
#if 0
  GumQuickApiResolver api_resolver;
  GumQuickSymbol symbol;
  GumQuickCModule cmodule;
#endif
  GumQuickInstruction instruction;
  GumQuickCodeWriter code_writer;
#if 0
  GumQuickCodeRelocator code_relocator;
#endif
  GumQuickStalker stalker;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
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
  GumQuickScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumPostData
{
  GumQuickScript * script;
  gchar * message;
  GBytes * data;
};

static void gum_quick_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_quick_script_dispose (GObject * object);
static void gum_quick_script_finalize (GObject * object);
static void gum_quick_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_quick_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_quick_script_destroy_context (GumQuickScript * self);

static void gum_quick_script_load (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_quick_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_quick_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_quick_script_do_load (GumScriptTask * task,
    GumQuickScript * self, gpointer task_data, GCancellable * cancellable);
static void gum_quick_script_perform_load_task (GumQuickScript * self,
    GumScriptTask * task);
static void gum_quick_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_quick_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_quick_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_quick_script_do_unload (GumScriptTask * task,
    GumQuickScript * self, gpointer task_data, GCancellable * cancellable);
static void gum_quick_script_complete_unload_task (GumQuickScript * self,
    GumScriptTask * task);
static void gum_quick_script_try_unload (GumQuickScript * self);
static void gum_quick_script_once_unloaded (GumQuickScript * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_quick_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_quick_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_quick_script_do_post (GumPostData * d);
static void gum_quick_post_data_free (GumPostData * d);

static GumStalker * gum_quick_script_get_stalker (GumScript * script);

static void gum_quick_script_emit (GumQuickScript * self,
    const gchar * message, GBytes * data);
static gboolean gum_quick_script_do_emit (GumEmitData * d);
static void gum_quick_emit_data_free (GumEmitData * d);

G_DEFINE_TYPE_EXTENDED (GumQuickScript,
                        gum_quick_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_quick_script_iface_init))

static void
gum_quick_script_class_init (GumQuickScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_script_dispose;
  object_class->finalize = gum_quick_script_finalize;
  object_class->get_property = gum_quick_script_get_property;
  object_class->set_property = gum_quick_script_set_property;

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
      GUM_QUICK_TYPE_SCRIPT_BACKEND,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_quick_script_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
  GumScriptInterface * iface = g_iface;

  iface->load = gum_quick_script_load;
  iface->load_finish = gum_quick_script_load_finish;
  iface->load_sync = gum_quick_script_load_sync;
  iface->unload = gum_quick_script_unload;
  iface->unload_finish = gum_quick_script_unload_finish;
  iface->unload_sync = gum_quick_script_unload_sync;

  iface->set_message_handler = gum_quick_script_set_message_handler;
  iface->post = gum_quick_script_post;

  iface->get_stalker = gum_quick_script_get_stalker;
}

static void
gum_quick_script_init (GumQuickScript * self)
{
  self->name = g_strdup ("agent");

  self->state = GUM_SCRIPT_STATE_UNLOADED;
  self->on_unload = NULL;
}

static void
gum_quick_script_dispose (GObject * object)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);
  GumScript * script = GUM_SCRIPT (self);

  gum_quick_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_quick_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    if (self->state == GUM_SCRIPT_STATE_UNLOADED && self->ctx != NULL)
      gum_quick_script_destroy_context (self);

    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_quick_script_parent_class)->dispose (object);
}

static void
gum_quick_script_finalize (GObject * object)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

  g_free (self->name);
  g_free (self->source);
  g_bytes_unref (self->bytecode);

  G_OBJECT_CLASS (gum_quick_script_parent_class)->finalize (object);
}

static void
gum_quick_script_get_property (GObject * object,
                               guint property_id,
                               GValue * value,
                               GParamSpec * pspec)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

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
gum_quick_script_set_property (GObject * object,
                               guint property_id,
                               const GValue * value,
                               GParamSpec * pspec)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

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
      self->backend = GUM_QUICK_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_quick_script_create_context (GumQuickScript * self,
                                 GError ** error)
{
  GumQuickCore * core = &self->core;
  JSRuntime * rt;
  JSContext * ctx;
  JSValue val;
  GumQuickScope scope = { core, NULL, };

  g_assert (self->ctx == NULL);

  rt = gum_quick_script_backend_make_runtime (self->backend);
  JS_SetRuntimeOpaque (rt, core);

  ctx = JS_NewContext (rt);
  JS_SetContextOpaque (ctx, core);

  if (self->bytecode != NULL)
  {
    val = gum_quick_script_backend_read_program (self->backend, ctx,
        self->bytecode, error);
  }
  else
  {
    val = gum_quick_script_backend_compile_program (self->backend, ctx,
        self->name, self->source, error);
  }
  if (JS_IsException (val))
    goto malformed_program;

  self->rt = rt;
  self->ctx = ctx;
  self->code = val;

  _gum_quick_core_init (core, self,
      gum_quick_script_backend_get_scope_mutex (self->backend),
      gumjs_frida_source_map, &self->interceptor, &self->stalker,
      gum_quick_script_emit,
      gum_quick_script_backend_get_scheduler (self->backend), self->ctx);

  core->current_scope = &scope;

#if 0
  _gum_quick_kernel_init (&self->kernel, core);
  _gum_quick_memory_init (&self->memory, core);
  _gum_quick_module_init (&self->module, core);
  _gum_quick_process_init (&self->process, &self->module, core);
  _gum_quick_thread_init (&self->thread, core);
  _gum_quick_file_init (&self->file, core);
  _gum_quick_stream_init (&self->stream, core);
  _gum_quick_socket_init (&self->socket, core);
  _gum_quick_database_init (&self->database, core);
#endif
  _gum_quick_interceptor_init (&self->interceptor, core);
#if 0
  _gum_quick_api_resolver_init (&self->api_resolver, core);
  _gum_quick_symbol_init (&self->symbol, core);
  _gum_quick_cmodule_init (&self->cmodule, core);
  _gum_quick_instruction_init (&self->instruction, core);
  _gum_quick_code_writer_init (&self->code_writer, core);
  _gum_quick_code_relocator_init (&self->code_relocator, &self->code_writer,
      &self->instruction, core);
#endif
  _gum_quick_stalker_init (&self->stalker, &self->code_writer,
      &self->instruction, core);

  core->current_scope = NULL;

  return TRUE;

malformed_program:
  {
    JS_FreeContext (ctx);
    JS_FreeRuntime (rt);

    return FALSE;
  }
}

static void
gum_quick_script_destroy_context (GumQuickScript * self)
{
  GumQuickCore * core = &self->core;

  g_assert (self->ctx != NULL);

  {
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);

    _gum_quick_stalker_dispose (&self->stalker);
#if 0
    _gum_quick_code_relocator_dispose (&self->code_relocator);
    _gum_quick_code_writer_dispose (&self->code_writer);
    _gum_quick_instruction_dispose (&self->instruction);
    _gum_quick_cmodule_dispose (&self->cmodule);
    _gum_quick_symbol_dispose (&self->symbol);
    _gum_quick_api_resolver_dispose (&self->api_resolver);
#endif
    _gum_quick_interceptor_dispose (&self->interceptor);
#if 0
    _gum_quick_database_dispose (&self->database);
    _gum_quick_socket_dispose (&self->socket);
    _gum_quick_stream_dispose (&self->stream);
    _gum_quick_file_dispose (&self->file);
    _gum_quick_thread_dispose (&self->thread);
    _gum_quick_process_dispose (&self->process);
    _gum_quick_module_dispose (&self->module);
    _gum_quick_memory_dispose (&self->memory);
    _gum_quick_kernel_dispose (&self->kernel);
#endif
    _gum_quick_core_dispose (core);

    _gum_quick_scope_leave (&scope);
  }

  {
    GumQuickScope scope = { core, NULL, };

    core->current_scope = &scope;

    JS_FreeValue (self->ctx, self->code);
    self->code = JS_NULL;

    JS_FreeContext (self->ctx);
    self->ctx = NULL;

    JS_FreeRuntime (self->rt);
    self->rt = NULL;

    core->current_scope = NULL;
  }

  _gum_quick_stalker_finalize (&self->stalker);
#if 0
  _gum_quick_code_relocator_finalize (&self->code_relocator);
  _gum_quick_code_writer_finalize (&self->code_writer);
  _gum_quick_instruction_finalize (&self->instruction);
  _gum_quick_cmodule_finalize (&self->cmodule);
  _gum_quick_symbol_finalize (&self->symbol);
  _gum_quick_api_resolver_finalize (&self->api_resolver);
#endif
  _gum_quick_interceptor_finalize (&self->interceptor);
#if 0
  _gum_quick_database_finalize (&self->database);
  _gum_quick_socket_finalize (&self->socket);
  _gum_quick_stream_finalize (&self->stream);
  _gum_quick_file_finalize (&self->file);
  _gum_quick_thread_finalize (&self->thread);
  _gum_quick_process_finalize (&self->process);
  _gum_quick_module_finalize (&self->module);
  _gum_quick_memory_finalize (&self->memory);
  _gum_quick_kernel_finalize (&self->kernel);
#endif
  _gum_quick_core_finalize (core);
}

static void
gum_quick_script_load (GumScript * script,
                       GCancellable * cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_load,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_quick_script_load_finish (GumScript * script,
                              GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_quick_script_load_sync (GumScript * script,
                            GCancellable * cancellable)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_load,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_quick_script_do_load (GumScriptTask * task,
                          GumQuickScript * self,
                          gpointer task_data,
                          GCancellable * cancellable)
{
  switch (self->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
    case GUM_SCRIPT_STATE_LOADED:
      gum_quick_script_perform_load_task (self, task);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_quick_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_quick_script_perform_load_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_quick_script_perform_load_task (GumQuickScript * self,
                                    GumScriptTask * task)
{
  if (self->state == GUM_SCRIPT_STATE_UNLOADED)
  {
    GumQuickScope scope;
    JSContext * ctx;
    JSValue result;

    if (self->ctx == NULL)
    {
      gum_quick_script_create_context (self, NULL);
    }

    ctx = self->ctx;

    _gum_quick_scope_enter (&scope, &self->core);

    gum_quick_bundle_load (gumjs_runtime_modules, ctx);

    result = JS_EvalFunction (ctx, self->code);
    self->code = JS_NULL;

    if (JS_IsException (result))
      _gum_quick_scope_catch_and_emit (&scope);

    JS_FreeValue (ctx, result);

    _gum_quick_scope_leave (&scope);

    self->state = GUM_SCRIPT_STATE_LOADED;
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_quick_script_unload (GumScript * script,
                         GCancellable * cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_quick_script_unload_finish (GumScript * script,
                                GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_quick_script_unload_sync (GumScript * script,
                              GCancellable * cancellable)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_quick_script_do_unload (GumScriptTask * task,
                            GumQuickScript * self,
                            gpointer task_data,
                            GCancellable * cancellable)
{
  switch (self->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
      gum_quick_script_complete_unload_task (self, task);
      break;
    case GUM_SCRIPT_STATE_LOADED:
      self->state = GUM_SCRIPT_STATE_UNLOADING;
      gum_quick_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_quick_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      gum_quick_script_try_unload (self);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_quick_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_quick_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_quick_script_complete_unload_task (GumQuickScript * self,
                                       GumScriptTask * task)
{
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_quick_script_try_unload (GumQuickScript * self)
{
  GumQuickScope scope;
  gboolean success;

  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  _gum_quick_scope_enter (&scope, &self->core);

  _gum_quick_stalker_flush (&self->stalker);
  _gum_quick_interceptor_flush (&self->interceptor);
#if 0
  _gum_quick_socket_flush (&self->socket);
  _gum_quick_stream_flush (&self->stream);
  _gum_quick_process_flush (&self->process);
#endif
  success = _gum_quick_core_flush (&self->core, gum_quick_script_try_unload);

  _gum_quick_scope_leave (&scope);

  if (success)
  {
    gum_quick_script_destroy_context (self);

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
gum_quick_script_once_unloaded (GumQuickScript * self,
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
gum_quick_script_set_message_handler (GumScript * script,
                                      GumScriptMessageHandler handler,
                                      gpointer data,
                                      GDestroyNotify data_destroy)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
}

static void
gum_quick_script_post (GumScript * script,
                       const gchar * message,
                       GBytes * data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumPostData * d;

  d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_quick_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_script_do_post, d,
      (GDestroyNotify) gum_quick_post_data_free);
}

static void
gum_quick_script_do_post (GumPostData * d)
{
  GBytes * data;

  data = d->data;
  d->data = NULL;

  _gum_quick_core_post (&d->script->core, d->message, data);
}

static void
gum_quick_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static GumStalker *
gum_quick_script_get_stalker (GumScript * script)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);

  return _gum_quick_stalker_get (&self->stalker);
}

static void
gum_quick_script_emit (GumQuickScript * self,
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
      (GSourceFunc) gum_quick_script_do_emit,
      d,
      (GDestroyNotify) gum_quick_emit_data_free);
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_quick_script_do_emit (GumEmitData * d)
{
  GumQuickScript * self = d->script;

  if (self->message_handler != NULL)
  {
    self->message_handler (GUM_SCRIPT (self), d->message, d->data,
        self->message_handler_data);
  }

  return FALSE;
}

static void
gum_quick_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}

void
_gum_quick_panic (JSContext * ctx,
                  const gchar * prefix)
{
  JSValue exception_val, stack_val;
  const char * message, * stack;

  exception_val = JS_GetException (ctx);

  message = JS_ToCString (ctx, exception_val);

  stack_val = JS_GetPropertyStr (ctx, exception_val, "stack");
  stack = JS_ToCString (ctx, stack_val);

  if (stack[0] != '\0')
    g_critical ("%s: %s [stack: %s]", prefix, message, stack);
  else
    g_critical ("%s: %s", prefix, message);

  JS_FreeCString (ctx, stack);
  JS_FreeCString (ctx, message);
  JS_FreeValue (ctx, stack_val);
  JS_FreeValue (ctx, exception_val);

  abort ();
}
