/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8script.h"

#include "gumscripttask.h"
#include "gumv8script-priv.h"

using namespace v8;

typedef void (* GumUnloadNotifyFunc) (GumV8Script * self, gpointer user_data);

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
                            gum_v8_script_iface_init));

static void
gum_v8_script_class_init (GumV8ScriptClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumV8ScriptPrivate));

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
}

static void
gum_v8_script_iface_init (gpointer g_iface,
                          gpointer iface_data)
{
  auto iface = (GumScriptIface *) g_iface;

  (void) iface_data;

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
  auto priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_V8_TYPE_SCRIPT, GumV8ScriptPrivate);

  priv->state = GUM_SCRIPT_STATE_UNLOADED;
  priv->on_unload = NULL;
}

static void
gum_v8_script_constructed (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto priv = self->priv;

  G_OBJECT_CLASS (gum_v8_script_parent_class)->constructed (object);

  priv->isolate = (Isolate *) gum_v8_script_backend_get_isolate (priv->backend);
}

static void
gum_v8_script_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto priv = self->priv;
  auto script = GUM_SCRIPT (self);

  gum_v8_script_set_message_handler (script, NULL, NULL, NULL);

  if (priv->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_v8_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    priv->isolate = NULL;

    g_clear_pointer (&priv->main_context, g_main_context_unref);
    g_clear_pointer (&priv->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_v8_script_parent_class)->dispose (object);
}

static void
gum_v8_script_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto priv = self->priv;

  g_free (priv->name);
  g_free (priv->source);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->finalize (object);
}

static void
gum_v8_script_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);
  auto priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, priv->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, priv->source);
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
gum_v8_script_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);
  auto priv = self->priv;

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
    case PROP_MAIN_CONTEXT:
      if (priv->main_context != NULL)
        g_main_context_unref (priv->main_context);
      priv->main_context = (GMainContext *) g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (priv->backend != NULL)
        g_object_unref (priv->backend);
      priv->backend = GUM_V8_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_v8_script_create_context (GumV8Script * self,
                              GError ** error)
{
  auto priv = self->priv;

  g_assert (priv->context == NULL);

  {
    Locker locker (priv->isolate);
    Isolate::Scope isolate_scope (priv->isolate);
    HandleScope handle_scope (priv->isolate);

    auto global_templ = ObjectTemplate::New ();
    auto platform =
        (GumV8Platform *) gum_v8_script_backend_get_platform (priv->backend);
    _gum_v8_core_init (&priv->core, self, platform->GetRuntimeSourceMap (),
        gum_v8_script_emit, gum_v8_script_backend_get_scheduler (priv->backend),
        priv->isolate, global_templ);
    _gum_v8_kernel_init (&priv->kernel, &priv->core, global_templ);
    _gum_v8_memory_init (&priv->memory, &priv->core, global_templ);
    _gum_v8_process_init (&priv->process, &priv->core, global_templ);
    _gum_v8_thread_init (&priv->thread, &priv->core, global_templ);
    _gum_v8_module_init (&priv->module, &priv->core, global_templ);
    _gum_v8_file_init (&priv->file, &priv->core, global_templ);
    _gum_v8_stream_init (&priv->stream, &priv->core, global_templ);
    _gum_v8_socket_init (&priv->socket, &priv->core, global_templ);
    _gum_v8_interceptor_init (&priv->interceptor, &priv->core,
        global_templ);
    _gum_v8_stalker_init (&priv->stalker, &priv->core, global_templ);
    _gum_v8_api_resolver_init (&priv->api_resolver, &priv->core, global_templ);
    _gum_v8_symbol_init (&priv->symbol, &priv->core, global_templ);
    _gum_v8_instruction_init (&priv->instruction, &priv->core,
        global_templ);

    auto context = Context::New (priv->isolate, NULL, global_templ);
    priv->context = new GumPersistent<Context>::type (priv->isolate, context);
    Context::Scope context_scope (context);
    _gum_v8_core_realize (&priv->core);
    _gum_v8_kernel_realize (&priv->kernel);
    _gum_v8_memory_realize (&priv->memory);
    _gum_v8_process_realize (&priv->process);
    _gum_v8_thread_realize (&priv->thread);
    _gum_v8_module_realize (&priv->module);
    _gum_v8_file_realize (&priv->file);
    _gum_v8_stream_realize (&priv->stream);
    _gum_v8_socket_realize (&priv->socket);
    _gum_v8_interceptor_realize (&priv->interceptor);
    _gum_v8_stalker_realize (&priv->stalker);
    _gum_v8_api_resolver_realize (&priv->api_resolver);
    _gum_v8_symbol_realize (&priv->symbol);
    _gum_v8_instruction_realize (&priv->instruction);

    auto resource_name_str = g_strconcat (priv->name, ".js", (gpointer) NULL);
    auto resource_name = String::NewFromUtf8 (priv->isolate, resource_name_str);
    ScriptOrigin origin (resource_name);
    g_free (resource_name_str);

    auto source = String::NewFromUtf8 (priv->isolate, priv->source);

    TryCatch trycatch;
    auto maybe_code = Script::Compile (context, source, &origin);
    Local<Script> code;
    if (maybe_code.ToLocal (&code))
    {
      priv->code = new GumPersistent<Script>::type (priv->isolate, code);
    }
    else
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (exception);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber (), *exception_str);
    }
  }

  if (priv->code == NULL)
  {
    gum_v8_script_destroy_context (self);
    return FALSE;
  }

  return TRUE;
}

static void
gum_v8_script_destroy_context (GumV8Script * self)
{
  auto priv = self->priv;

  g_assert (priv->context != NULL);

  {
    ScriptScope scope (self);

    _gum_v8_instruction_dispose (&priv->instruction);
    _gum_v8_symbol_dispose (&priv->symbol);
    _gum_v8_api_resolver_dispose (&priv->api_resolver);
    _gum_v8_stalker_dispose (&priv->stalker);
    _gum_v8_interceptor_dispose (&priv->interceptor);
    _gum_v8_socket_dispose (&priv->socket);
    _gum_v8_stream_dispose (&priv->stream);
    _gum_v8_file_dispose (&priv->file);
    _gum_v8_module_dispose (&priv->module);
    _gum_v8_thread_dispose (&priv->thread);
    _gum_v8_process_dispose (&priv->process);
    _gum_v8_memory_dispose (&priv->memory);
    _gum_v8_kernel_dispose (&priv->kernel);
    _gum_v8_core_dispose (&priv->core);
  }

  delete priv->code;
  priv->code = nullptr;
  delete priv->context;
  priv->context = nullptr;

  _gum_v8_instruction_finalize (&priv->instruction);
  _gum_v8_symbol_finalize (&priv->symbol);
  _gum_v8_api_resolver_finalize (&priv->api_resolver);
  _gum_v8_stalker_finalize (&priv->stalker);
  _gum_v8_interceptor_finalize (&priv->interceptor);
  _gum_v8_socket_finalize (&priv->socket);
  _gum_v8_stream_finalize (&priv->stream);
  _gum_v8_file_finalize (&priv->file);
  _gum_v8_module_finalize (&priv->module);
  _gum_v8_thread_finalize (&priv->thread);
  _gum_v8_process_finalize (&priv->process);
  _gum_v8_memory_finalize (&priv->memory);
  _gum_v8_kernel_finalize (&priv->kernel);
  _gum_v8_core_finalize (&priv->core);
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
      gum_v8_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_v8_script_load_finish (GumScript * script,
                           GAsyncResult * result)
{
  (void) script;

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
      gum_v8_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_load (GumScriptTask * task,
                       GumV8Script * self,
                       gpointer task_data,
                       GCancellable * cancellable)
{
  (void) task_data;
  (void) cancellable;

  switch (self->priv->state)
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
  auto priv = self->priv;

  if (priv->state == GUM_SCRIPT_STATE_UNLOADED)
  {
    if (priv->code == NULL)
    {
      auto created = gum_v8_script_create_context (self, NULL);
      g_assert (created);
    }

    {
      ScriptScope scope (self);
      auto platform =
          (GumV8Platform *) gum_v8_script_backend_get_platform (priv->backend);

      gum_v8_bundle_run (platform->GetRuntimeBundle ());

      auto code = Local<Script>::New (priv->isolate, *priv->code);
      code->Run ();
    }

    priv->state = GUM_SCRIPT_STATE_LOADED;
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
      gum_v8_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_v8_script_unload_finish (GumScript * script,
                             GAsyncResult * result)
{
  (void) script;

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
      gum_v8_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_unload (GumScriptTask * task,
                         GumV8Script * self,
                         gpointer task_data,
                         GCancellable * cancellable)
{
  auto priv = self->priv;

  (void) task_data;
  (void) cancellable;

  switch (priv->state)
  {
    case GUM_SCRIPT_STATE_UNLOADED:
      gum_v8_script_complete_unload_task (self, task);
      break;
    case GUM_SCRIPT_STATE_LOADED:
      priv->state = GUM_SCRIPT_STATE_UNLOADING;
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
  (void) self;

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_v8_script_try_unload (GumV8Script * self)
{
  auto priv = self->priv;

  g_assert_cmpuint (priv->state, ==, GUM_SCRIPT_STATE_UNLOADING);

  gboolean success;

  {
    ScriptScope scope (self);

    _gum_v8_stalker_flush (&priv->stalker);
    _gum_v8_interceptor_flush (&priv->interceptor);
    _gum_v8_socket_flush (&priv->socket);
    _gum_v8_stream_flush (&priv->stream);
    _gum_v8_process_flush (&priv->process);
    success = _gum_v8_core_flush (&priv->core, gum_v8_script_try_unload);
  }

  if (success)
  {
    gum_v8_script_destroy_context (self);

    priv->state = GUM_SCRIPT_STATE_UNLOADED;

    while (priv->on_unload != NULL)
    {
      auto link = priv->on_unload;
      auto callback = (GumUnloadNotifyCallback *) link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      priv->on_unload = g_slist_delete_link (priv->on_unload, link);
    }
  }
}

static void
gum_v8_script_once_unloaded (GumV8Script * self,
                             GumUnloadNotifyFunc func,
                             gpointer data,
                             GDestroyNotify data_destroy)
{
  auto priv = self->priv;

  auto callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  priv->on_unload = g_slist_append (priv->on_unload, callback);
}

static void
gum_v8_script_set_message_handler (GumScript * script,
                                   GumScriptMessageHandler handler,
                                   gpointer data,
                                   GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT (script);
  auto priv = self->priv;

  if (priv->message_handler_data_destroy != NULL)
    priv->message_handler_data_destroy (priv->message_handler_data);
  priv->message_handler = handler;
  priv->message_handler_data = data;
  priv->message_handler_data_destroy = data_destroy;
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
      gum_v8_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_v8_script_do_post, d,
      (GDestroyNotify) gum_v8_post_data_free);
}

static void
gum_v8_script_do_post (GumPostData * d)
{
  GBytes * data = d->data;
  d->data = NULL;

  _gum_v8_core_post (&d->script->priv->core, d->message, data);
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

  return _gum_v8_stalker_get (&self->priv->stalker);
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
  g_source_attach (source, self->priv->main_context);
  g_source_unref (source);
}

static gboolean
gum_v8_script_do_emit (GumEmitData * d)
{
  auto self = d->script;
  auto priv = self->priv;

  if (priv->message_handler != NULL)
  {
    priv->message_handler (GUM_SCRIPT (self), d->message, d->data,
        priv->message_handler_data);
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
