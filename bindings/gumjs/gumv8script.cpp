/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8script.h"

#include "gumscripttask.h"
#include "gumv8script-priv.h"
#include "gumv8value.h"

using namespace v8;

typedef void (* GumUnloadNotifyFunc) (GumV8Script * self, gpointer user_data);

enum
{
  CONTEXT_CREATED,
  CONTEXT_DESTROYED,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

enum _GumScriptState
{
  GUM_SCRIPT_STATE_UNLOADED = 1,
  GUM_SCRIPT_STATE_LOADED,
  GUM_SCRIPT_STATE_UNLOADING
};

struct GumUnloadNotifyCallback
{
  GumUnloadNotifyFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct GumEmitData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

struct GumPostData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

static void gum_v8_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_v8_script_constructed (GObject * object);
static void gum_v8_script_dispose (GObject * object);
static void gum_v8_script_finalize (GObject * object);
static void gum_v8_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_v8_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_v8_script_destroy_context (GumV8Script * self);

static void gum_v8_script_load (GumScript * script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_v8_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_load (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_perform_load_task (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_v8_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_unload (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_complete_unload_task (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_try_unload (GumV8Script * self);
static void gum_v8_script_once_unloaded (GumV8Script * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_v8_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_v8_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_v8_script_do_post (GumPostData * d);
static void gum_v8_post_data_free (GumPostData * d);

static GumStalker * gum_v8_script_get_stalker (GumScript * script);

static void gum_v8_script_emit (GumV8Script * self, const gchar * message,
    GBytes * data);
static gboolean gum_v8_script_do_emit (GumEmitData * d);
static void gum_v8_emit_data_free (GumEmitData * d);

G_DEFINE_TYPE_EXTENDED (GumV8Script,
                        gum_v8_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_v8_script_iface_init))

static guint gum_v8_script_signals[LAST_SIGNAL] = { 0, };

static void
gum_v8_script_class_init (GumV8ScriptClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_v8_script_constructed;
  object_class->dispose = gum_v8_script_dispose;
  object_class->finalize = gum_v8_script_finalize;
  object_class->get_property = gum_v8_script_get_property;
  object_class->set_property = gum_v8_script_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_V8_TYPE_SCRIPT_BACKEND,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));

  gum_v8_script_signals[CONTEXT_CREATED] = g_signal_new ("context-created",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
  gum_v8_script_signals[CONTEXT_DESTROYED] = g_signal_new ("context-destroyed",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static void
gum_v8_script_iface_init (gpointer g_iface,
                          gpointer iface_data)
{
  auto iface = (GumScriptInterface *) g_iface;

  iface->load = gum_v8_script_load;
  iface->load_finish = gum_v8_script_load_finish;
  iface->load_sync = gum_v8_script_load_sync;
  iface->unload = gum_v8_script_unload;
  iface->unload_finish = gum_v8_script_unload_finish;
  iface->unload_sync = gum_v8_script_unload_sync;

  iface->set_message_handler = gum_v8_script_set_message_handler;
  iface->post = gum_v8_script_post;

  iface->get_stalker = gum_v8_script_get_stalker;
}

static void
gum_v8_script_init (GumV8Script * self)
{
  self->state = GUM_SCRIPT_STATE_UNLOADED;
  self->on_unload = NULL;
}

static void
gum_v8_script_constructed (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->constructed (object);

  self->isolate = (Isolate *) gum_v8_script_backend_get_isolate (self->backend);
}

static void
gum_v8_script_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto script = GUM_SCRIPT (self);

  gum_v8_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_v8_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    self->isolate = NULL;

    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_v8_script_parent_class)->dispose (object);
}

static void
gum_v8_script_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  g_free (self->name);
  g_free (self->source);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->finalize (object);
}

static void
gum_v8_script_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, self->source);
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
gum_v8_script_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

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
    case PROP_MAIN_CONTEXT:
      if (self->main_context != NULL)
        g_main_context_unref (self->main_context);
      self->main_context = (GMainContext *) g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (self->backend != NULL)
        g_object_unref (self->backend);
      self->backend = GUM_V8_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_v8_script_create_context (GumV8Script * self,
                              GError ** error)
{
  g_assert (self->context == NULL);

  {
    Isolate * isolate = self->isolate;
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    auto global_templ = ObjectTemplate::New (isolate);
    auto platform =
        (GumV8Platform *) gum_v8_script_backend_get_platform (self->backend);
    _gum_v8_core_init (&self->core, self, platform->GetRuntimeSourceMap (),
        gum_v8_script_emit, gum_v8_script_backend_get_scheduler (self->backend),
        isolate, global_templ);
    _gum_v8_kernel_init (&self->kernel, &self->core, global_templ);
    _gum_v8_memory_init (&self->memory, &self->core, global_templ);
    _gum_v8_module_init (&self->module, &self->core, global_templ);
    _gum_v8_process_init (&self->process, &self->module, &self->core,
        global_templ);
    _gum_v8_thread_init (&self->thread, &self->core, global_templ);
    _gum_v8_file_init (&self->file, &self->core, global_templ);
    _gum_v8_stream_init (&self->stream, &self->core, global_templ);
    _gum_v8_socket_init (&self->socket, &self->core, global_templ);
    _gum_v8_database_init (&self->database, &self->core, global_templ);
    _gum_v8_interceptor_init (&self->interceptor, &self->core,
        global_templ);
    _gum_v8_api_resolver_init (&self->api_resolver, &self->core, global_templ);
    _gum_v8_symbol_init (&self->symbol, &self->core, global_templ);
    _gum_v8_cmodule_init (&self->cmodule, &self->core, global_templ);
    _gum_v8_instruction_init (&self->instruction, &self->core, global_templ);
    _gum_v8_code_writer_init (&self->code_writer, &self->core, global_templ);
    _gum_v8_code_relocator_init (&self->code_relocator, &self->code_writer,
        &self->instruction, &self->core, global_templ);
    _gum_v8_stalker_init (&self->stalker, &self->code_writer,
        &self->instruction, &self->core, global_templ);

    Local<Context> context (Context::New (isolate, NULL, global_templ));
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_CREATED], 0, &context);
    self->context = new GumPersistent<Context>::type (isolate, context);
    Context::Scope context_scope (context);
    _gum_v8_core_realize (&self->core);
    _gum_v8_kernel_realize (&self->kernel);
    _gum_v8_memory_realize (&self->memory);
    _gum_v8_module_realize (&self->module);
    _gum_v8_process_realize (&self->process);
    _gum_v8_thread_realize (&self->thread);
    _gum_v8_file_realize (&self->file);
    _gum_v8_stream_realize (&self->stream);
    _gum_v8_socket_realize (&self->socket);
    _gum_v8_database_realize (&self->database);
    _gum_v8_interceptor_realize (&self->interceptor);
    _gum_v8_api_resolver_realize (&self->api_resolver);
    _gum_v8_symbol_realize (&self->symbol);
    _gum_v8_cmodule_realize (&self->cmodule);
    _gum_v8_instruction_realize (&self->instruction);
    _gum_v8_code_writer_realize (&self->code_writer);
    _gum_v8_code_relocator_realize (&self->code_relocator);
    _gum_v8_stalker_realize (&self->stalker);

    auto resource_name_str = g_strconcat ("/", self->name, ".js", NULL);
    auto resource_name = String::NewFromUtf8 (isolate, resource_name_str);
    ScriptOrigin origin (resource_name);
    g_free (resource_name_str);

    auto source = String::NewFromUtf8 (isolate, self->source);

    TryCatch trycatch (isolate);
    auto maybe_code = Script::Compile (context, source, &origin);
    Local<Script> code;
    if (maybe_code.ToLocal (&code))
    {
      self->code = new GumPersistent<Script>::type (isolate, code);
    }
    else
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (isolate, exception);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber (context).FromMaybe (-1), *exception_str);
    }
  }

  if (self->code == NULL)
  {
    gum_v8_script_destroy_context (self);
    return FALSE;
  }

  return TRUE;
}

static void
gum_v8_script_destroy_context (GumV8Script * self)
{
  g_assert (self->context != NULL);

  {
    ScriptScope scope (self);

    _gum_v8_stalker_dispose (&self->stalker);
    _gum_v8_code_relocator_dispose (&self->code_relocator);
    _gum_v8_code_writer_dispose (&self->code_writer);
    _gum_v8_instruction_dispose (&self->instruction);
    _gum_v8_cmodule_dispose (&self->cmodule);
    _gum_v8_symbol_dispose (&self->symbol);
    _gum_v8_api_resolver_dispose (&self->api_resolver);
    _gum_v8_interceptor_dispose (&self->interceptor);
    _gum_v8_database_dispose (&self->database);
    _gum_v8_socket_dispose (&self->socket);
    _gum_v8_stream_dispose (&self->stream);
    _gum_v8_file_dispose (&self->file);
    _gum_v8_thread_dispose (&self->thread);
    _gum_v8_process_dispose (&self->process);
    _gum_v8_module_dispose (&self->module);
    _gum_v8_memory_dispose (&self->memory);
    _gum_v8_kernel_dispose (&self->kernel);
    _gum_v8_core_dispose (&self->core);

    auto context = Local<Context>::New (self->isolate, *self->context);
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_DESTROYED], 0, &context);
  }

  delete self->code;
  self->code = nullptr;
  delete self->context;
  self->context = nullptr;

  _gum_v8_stalker_finalize (&self->stalker);
  _gum_v8_code_relocator_finalize (&self->code_relocator);
  _gum_v8_code_writer_finalize (&self->code_writer);
  _gum_v8_instruction_finalize (&self->instruction);
  _gum_v8_cmodule_finalize (&self->cmodule);
  _gum_v8_symbol_finalize (&self->symbol);
  _gum_v8_api_resolver_finalize (&self->api_resolver);
  _gum_v8_interceptor_finalize (&self->interceptor);
  _gum_v8_database_finalize (&self->database);
  _gum_v8_socket_finalize (&self->socket);
  _gum_v8_stream_finalize (&self->stream);
  _gum_v8_file_finalize (&self->file);
  _gum_v8_thread_finalize (&self->thread);
  _gum_v8_process_finalize (&self->process);
  _gum_v8_module_finalize (&self->module);
  _gum_v8_memory_finalize (&self->memory);
  _gum_v8_kernel_finalize (&self->kernel);
  _gum_v8_core_finalize (&self->core);
}

static void
gum_v8_script_load (GumScript * script,
                    GCancellable * cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_load_finish (GumScript * script,
                           GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_load_sync (GumScript * script,
                         GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_load (GumScriptTask * task,
                       GumV8Script * self,
                       gpointer task_data,
                       GCancellable * cancellable)
{
  switch (self->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
    case GUM_SCRIPT_STATE_LOADED:
      gum_v8_script_perform_load_task (self, task);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_v8_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_v8_script_perform_load_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_script_perform_load_task (GumV8Script * self,
                                 GumScriptTask * task)
{
  if (self->state == GUM_SCRIPT_STATE_UNLOADED)
  {
    if (self->code == NULL)
    {
      gum_v8_script_create_context (self, NULL);
    }

    {
      ScriptScope scope (self);
      auto isolate = self->isolate;

      auto platform =
          (GumV8Platform *) gum_v8_script_backend_get_platform (self->backend);
      gum_v8_bundle_run (platform->GetRuntimeBundle ());

      auto code = Local<Script>::New (isolate, *self->code);
      auto result = code->Run (isolate->GetCurrentContext ());
      _gum_v8_ignore_result (result);
    }

    self->state = GUM_SCRIPT_STATE_LOADED;
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_v8_script_unload (GumScript * script,
                      GCancellable * cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_unload_finish (GumScript * script,
                             GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_unload_sync (GumScript * script,
                           GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_unload (GumScriptTask * task,
                         GumV8Script * self,
                         gpointer task_data,
                         GCancellable * cancellable)
{
  switch (self->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
      gum_v8_script_complete_unload_task (self, task);
      break;
    case GUM_SCRIPT_STATE_LOADED:
      self->state = GUM_SCRIPT_STATE_UNLOADING;
      gum_v8_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_v8_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      gum_v8_script_try_unload (self);
      break;
    case GUM_SCRIPT_STATE_UNLOADING:
      gum_v8_script_once_unloaded (self,
          (GumUnloadNotifyFunc) gum_v8_script_complete_unload_task,
          g_object_ref (task), g_object_unref);
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_script_complete_unload_task (GumV8Script * self,
                                    GumScriptTask * task)
{
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_v8_script_try_unload (GumV8Script * self)
{
  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  gboolean success;

  {
    ScriptScope scope (self);

    _gum_v8_stalker_flush (&self->stalker);
    _gum_v8_interceptor_flush (&self->interceptor);
    _gum_v8_socket_flush (&self->socket);
    _gum_v8_stream_flush (&self->stream);
    _gum_v8_process_flush (&self->process);
    success = _gum_v8_core_flush (&self->core, gum_v8_script_try_unload);
  }

  if (success)
  {
    gum_v8_script_destroy_context (self);

    self->state = GUM_SCRIPT_STATE_UNLOADED;

    while (self->on_unload != NULL)
    {
      auto link = self->on_unload;
      auto callback = (GumUnloadNotifyCallback *) link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      self->on_unload = g_slist_delete_link (self->on_unload, link);
    }
  }
}

static void
gum_v8_script_once_unloaded (GumV8Script * self,
                             GumUnloadNotifyFunc func,
                             gpointer data,
                             GDestroyNotify data_destroy)
{
  auto callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  self->on_unload = g_slist_append (self->on_unload, callback);
}

static void
gum_v8_script_set_message_handler (GumScript * script,
                                   GumScriptMessageHandler handler,
                                   gpointer data,
                                   GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
}

static void
gum_v8_script_post (GumScript * script,
                    const gchar * message,
                    GBytes * data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_v8_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_v8_script_do_post, d,
      (GDestroyNotify) gum_v8_post_data_free);
}

static void
gum_v8_script_do_post (GumPostData * d)
{
  GBytes * data = d->data;
  d->data = NULL;

  _gum_v8_core_post (&d->script->core, d->message, data);
}

static void
gum_v8_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static GumStalker *
gum_v8_script_get_stalker (GumScript * script)
{
  auto self = GUM_V8_SCRIPT (script);

  return _gum_v8_stalker_get (&self->stalker);
}

static void
gum_v8_script_emit (GumV8Script * self,
                    const gchar * message,
                    GBytes * data)
{
  auto d = g_slice_new (GumEmitData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_script_do_emit, d,
      (GDestroyNotify) gum_v8_emit_data_free);
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_v8_script_do_emit (GumEmitData * d)
{
  auto self = d->script;

  if (self->message_handler != NULL)
  {
    self->message_handler (GUM_SCRIPT (self), d->message, d->data,
        self->message_handler_data);
  }

  return FALSE;
}

static void
gum_v8_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}
