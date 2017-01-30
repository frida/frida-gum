/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8scriptbackend.h"

#include "gumscripttask.h"
#include "gumv8platform.h"
#include "gumv8script.h"

#include <gum/guminterceptor.h>
#include <string.h>
#include <v8-debug.h>

#define GUM_V8_SCRIPT_BACKEND_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_V8_SCRIPT_BACKEND_UNLOCK() (g_mutex_unlock (&priv->mutex))

#define GUM_V8_SCRIPT_BACKEND_GET_PLATFORM(backend) \
    ((GumV8Platform *) gum_v8_script_backend_get_platform (backend))
#define GUM_V8_SCRIPT_BACKEND_GET_ISOLATE(backend) \
    ((Isolate *) gum_v8_script_backend_get_isolate (backend))

#define GUM_V8_FLAGS \
    "--es-staging " \
    "--harmony-array-prototype-values " \
    "--harmony-function-sent " \
    "--harmony-sharedarraybuffer " \
    "--harmony-simd " \
    "--harmony-do-expressions " \
    "--harmony-regexp-named-captures " \
    "--harmony-regexp-property " \
    "--harmony-class-fields " \
    "--harmony-async-iteration " \
    "--harmony-regexp-lookbehind " \
    "--harmony-tailcalls " \
    "--harmony-trailing-commas " \
    "--harmony-object-rest-spread " \
    "--wasm-simd-prototype " \
    "--wasm-eh-prototype " \
    "--wasm-mv-prototype " \
    "--wasm-atomics-prototype " \
    "--expose-gc"

using namespace v8;

template <typename T>
struct GumPersistent
{
  typedef Persistent<T, CopyablePersistentTraits<T> > type;
};

struct _GumV8ScriptBackendPrivate
{
  GMutex mutex;

  GumV8Platform * platform;

  GumScriptBackendDebugMessageHandler debug_handler;
  gpointer debug_handler_data;
  GDestroyNotify debug_handler_data_destroy;
  GMainContext * debug_handler_context;
  GumPersistent<Context>::type * debug_context;
};

struct GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

struct GumCreateScriptFromBytesData
{
  gchar * name;
  GBytes * bytes;
};

struct GumCompileScriptData
{
  gchar * source;
};

struct GumEmitDebugMessageData
{
  GumV8ScriptBackend * backend;
  gchar * message;
};

static void gum_v8_script_backend_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_script_backend_dispose (GObject * object);
static void gum_v8_script_backend_finalize (GObject * object);

static void gum_v8_script_backend_create (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_v8_script_backend_create_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_v8_script_backend_create_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_task_new (GumV8ScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_create_script_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCreateScriptData * d,
    GCancellable * cancellable);
static void gum_create_script_data_free (GumCreateScriptData * d);
static void gum_v8_script_backend_create_from_bytes (GumScriptBackend * backend,
    const gchar * name, GBytes * bytes, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_v8_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_v8_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumV8ScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCreateScriptFromBytesData * d,
    GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_v8_script_backend_compile (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_v8_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumV8ScriptBackend * backend, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_compile_script_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCompileScriptData * d,
    GCancellable * cancellable);
static void gum_compile_script_data_free (GumCompileScriptData * d);

static void gum_v8_script_backend_set_debug_message_handler (
    GumScriptBackend * backend, GumScriptBackendDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
static void gum_v8_script_backend_enable_debugger (GumV8ScriptBackend * self);
static void gum_v8_script_backend_disable_debugger (GumV8ScriptBackend * self);
static void gum_v8_script_backend_emit_debug_message (
    const Debug::Message & message);
static gboolean gum_v8_script_backend_do_emit_debug_message (
    GumEmitDebugMessageData * d);
static void gum_emit_debug_message_data_free (GumEmitDebugMessageData * d);
static void gum_v8_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);
static void gum_v8_script_backend_do_process_debug_messages (
    GumV8ScriptBackend * self);
static GMainContext * gum_v8_script_backend_get_main_context (
    GumScriptBackend * backend);

G_DEFINE_TYPE_EXTENDED (GumV8ScriptBackend,
                        gum_v8_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_v8_script_backend_iface_init));

static void
gum_v8_script_backend_class_init (GumV8ScriptBackendClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumV8ScriptBackendPrivate));

  object_class->dispose = gum_v8_script_backend_dispose;
  object_class->finalize = gum_v8_script_backend_finalize;
}

static void
gum_v8_script_backend_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  auto iface = (GumScriptBackendIface *) g_iface;

  (void) iface_data;

  iface->create = gum_v8_script_backend_create;
  iface->create_finish = gum_v8_script_backend_create_finish;
  iface->create_sync = gum_v8_script_backend_create_sync;
  iface->create_from_bytes = gum_v8_script_backend_create_from_bytes;
  iface->create_from_bytes_finish =
      gum_v8_script_backend_create_from_bytes_finish;
  iface->create_from_bytes_sync = gum_v8_script_backend_create_from_bytes_sync;

  iface->compile = gum_v8_script_backend_compile;
  iface->compile_finish = gum_v8_script_backend_compile_finish;
  iface->compile_sync = gum_v8_script_backend_compile_sync;

  iface->set_debug_message_handler =
      gum_v8_script_backend_set_debug_message_handler;
  iface->post_debug_message = gum_v8_script_backend_post_debug_message;

  iface->get_main_context = gum_v8_script_backend_get_main_context;
}

static void
gum_v8_script_backend_init (GumV8ScriptBackend * self)
{
  auto priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_V8_TYPE_SCRIPT_BACKEND, GumV8ScriptBackendPrivate);

  g_mutex_init (&priv->mutex);

  priv->platform = NULL;
}

static void
gum_v8_script_backend_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);
  auto priv = self->priv;

  g_clear_pointer (&priv->debug_handler_context, g_main_context_unref);
  if (priv->debug_handler_data_destroy != NULL)
    priv->debug_handler_data_destroy (priv->debug_handler_data);
  priv->debug_handler = NULL;
  priv->debug_handler_data = NULL;
  priv->debug_handler_data_destroy = NULL;

  gum_v8_script_backend_disable_debugger (self);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->dispose (object);
}

static void
gum_v8_script_backend_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);
  auto priv = self->priv;

  delete priv->platform;

  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->finalize (object);
}

gpointer
gum_v8_script_backend_get_platform (GumV8ScriptBackend * self)
{
  auto priv = self->priv;

  if (priv->platform == NULL)
  {
    V8::SetFlagsFromString (GUM_V8_FLAGS, (int) strlen (GUM_V8_FLAGS));
    priv->platform = new GumV8Platform ();
    priv->platform->GetIsolate ()->SetData (0, self);
  }

  return priv->platform;
}

gpointer
gum_v8_script_backend_get_isolate (GumV8ScriptBackend * self)
{
  return GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetIsolate ();
}

GumScriptScheduler *
gum_v8_script_backend_get_scheduler (GumV8ScriptBackend * self)
{
  return GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetScheduler ();
}

static void
gum_v8_script_backend_create (GumScriptBackend * backend,
                              const gchar * name,
                              const gchar * source,
                              GCancellable * cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_task_new (self, name, source, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_v8_script_backend_create_finish (GumScriptBackend * backend,
                                     GAsyncResult * result,
                                     GError ** error)
{
  (void) backend;

  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_v8_script_backend_create_sync (GumScriptBackend * backend,
                                   const gchar * name,
                                   const gchar * source,
                                   GCancellable * cancellable,
                                   GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_task_new (self, name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_task_new (GumV8ScriptBackend * backend,
                            const gchar * name,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  auto d = g_slice_new (GumCreateScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_data_free);
  return task;
}

static void
gum_create_script_task_run (GumScriptTask * task,
                            GumV8ScriptBackend * self,
                            GumCreateScriptData * d,
                            GCancellable * cancellable)
{
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  (void) cancellable;

  auto script = GUM_V8_SCRIPT (g_object_new (GUM_V8_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL));

  GError * error = NULL;

  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    gum_v8_script_create_context (script, &error);
  }

  if (error == NULL)
  {
    gum_script_task_return_pointer (task, script, g_object_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);
    g_object_unref (script);
  }
}

static void
gum_create_script_data_free (GumCreateScriptData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumCreateScriptData, d);
}

static void
gum_v8_script_backend_create_from_bytes (GumScriptBackend * backend,
                                         const gchar * name,
                                         GBytes * bytes,
                                         GCancellable * cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, name, bytes,
      cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_v8_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                GAsyncResult * result,
                                                GError ** error)
{
  (void) backend;

  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_v8_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                              const gchar * name,
                                              GBytes * bytes,
                                              GCancellable * cancellable,
                                              GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, name, bytes,
      cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumV8ScriptBackend * backend,
                                       const gchar * name,
                                       GBytes * bytes,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  auto d = g_slice_new (GumCreateScriptFromBytesData);
  d->name = g_strdup (name);
  d->bytes = g_bytes_ref (bytes);

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_from_bytes_task_run, backend,
      cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_from_bytes_data_free);
  return task;
}

static void
gum_create_script_from_bytes_task_run (GumScriptTask * task,
                                       GumV8ScriptBackend * self,
                                       GumCreateScriptFromBytesData * d,
                                       GCancellable * cancellable)
{
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  (void) isolate;
  (void) d;
  (void) cancellable;

  auto error = g_error_new (G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "not yet supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_create_script_from_bytes_data_free (GumCreateScriptFromBytesData * d)
{
  g_free (d->name);
  g_bytes_unref (d->bytes);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_v8_script_backend_compile (GumScriptBackend * backend,
                               const gchar * source,
                               GCancellable * cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_compile_script_task_new (self, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_v8_script_backend_compile_finish (GumScriptBackend * backend,
                                      GAsyncResult * result,
                                      GError ** error)
{
  (void) backend;

  return (GBytes *) gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result),
      error);
}

static GBytes *
gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
                                    const gchar * source,
                                    GCancellable * cancellable,
                                    GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task =
      gum_compile_script_task_new (self, source, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto bytes = (GBytes *) gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumV8ScriptBackend * backend,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  auto d = g_slice_new (GumCompileScriptData);
  d->source = g_strdup (source);

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_compile_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_compile_script_data_free);
  return task;
}

static void
gum_compile_script_task_run (GumScriptTask * task,
                             GumV8ScriptBackend * self,
                             GumCompileScriptData * d,
                             GCancellable * cancellable)
{
  Isolate * isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  (void) isolate;
  (void) d;
  (void) cancellable;

  auto error = g_error_new (G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "not yet supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->source);

  g_slice_free (GumCompileScriptData, d);
}

static void
gum_v8_script_backend_set_debug_message_handler (
    GumScriptBackend * backend,
    GumScriptBackendDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);
  auto priv = self->priv;

  if (priv->debug_handler_data_destroy != NULL)
    priv->debug_handler_data_destroy (priv->debug_handler_data);

  priv->debug_handler = handler;
  priv->debug_handler_data = data;
  priv->debug_handler_data_destroy = data_destroy;

  auto new_context = (handler != NULL)
      ? g_main_context_ref_thread_default ()
      : NULL;

  GUM_V8_SCRIPT_BACKEND_LOCK ();
  auto old_context = priv->debug_handler_context;
  priv->debug_handler_context = new_context;
  GUM_V8_SCRIPT_BACKEND_UNLOCK ();

  if (old_context != NULL)
    g_main_context_unref (old_context);

  gum_script_scheduler_push_job_on_js_thread (
      gum_v8_script_backend_get_scheduler (self), G_PRIORITY_DEFAULT,
      (handler != NULL)
          ? (GumScriptJobFunc) gum_v8_script_backend_enable_debugger
          : (GumScriptJobFunc) gum_v8_script_backend_disable_debugger,
      self, NULL);
}

static void
gum_v8_script_backend_enable_debugger (GumV8ScriptBackend * self)
{
  auto priv = self->priv;
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  Debug::SetMessageHandler (isolate, gum_v8_script_backend_emit_debug_message);

  auto context = Debug::GetDebugContext (isolate);
  priv->debug_context = new GumPersistent<Context>::type (isolate, context);
  Context::Scope context_scope (context);

  gum_v8_bundle_run (
      GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetDebugBundle ());
}

static void
gum_v8_script_backend_disable_debugger (GumV8ScriptBackend * self)
{
  auto priv = self->priv;
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  delete priv->debug_context;
  priv->debug_context = nullptr;

  Debug::SetMessageHandler (isolate, nullptr);
}

static void
gum_v8_script_backend_emit_debug_message (const Debug::Message & message)
{
  auto isolate = message.GetIsolate ();
  auto self = GUM_V8_SCRIPT_BACKEND (isolate->GetData (0));
  auto priv = self->priv;

  HandleScope scope (isolate);

  auto json = message.GetJSON ();
  String::Utf8Value json_str (json);

  GUM_V8_SCRIPT_BACKEND_LOCK ();
  auto context = (priv->debug_handler_context != NULL)
      ? g_main_context_ref (priv->debug_handler_context)
      : NULL;
  GUM_V8_SCRIPT_BACKEND_UNLOCK ();

  if (context == NULL)
    return;

  auto d = g_slice_new (GumEmitDebugMessageData);
  d->backend = self;
  g_object_ref (self);
  d->message = g_strdup (*json_str);

  auto source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_script_backend_do_emit_debug_message, d,
      (GDestroyNotify) gum_emit_debug_message_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_v8_script_backend_do_emit_debug_message (GumEmitDebugMessageData * d)
{
  auto priv = d->backend->priv;

  if (priv->debug_handler != NULL)
    priv->debug_handler (d->message, priv->debug_handler_data);

  return FALSE;
}

static void
gum_emit_debug_message_data_free (GumEmitDebugMessageData * d)
{
  g_free (d->message);
  g_object_unref (d->backend);

  g_slice_free (GumEmitDebugMessageData, d);
}

static void
gum_v8_script_backend_post_debug_message (GumScriptBackend * backend,
                                          const gchar * message)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);
  auto priv = self->priv;

  if (priv->debug_handler == NULL)
    return;

  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  glong command_length;
  uint16_t * command = g_utf8_to_utf16 (message, (glong) strlen (message), NULL,
      &command_length, NULL);
  g_assert (command != NULL);

  Debug::SendCommand (isolate, command, command_length);

  g_free (command);

  gum_script_scheduler_push_job_on_js_thread (
      gum_v8_script_backend_get_scheduler (self), G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) gum_v8_script_backend_do_process_debug_messages,
      self, NULL);
}

static void
gum_v8_script_backend_do_process_debug_messages (GumV8ScriptBackend * self)
{
  auto priv = self->priv;
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  auto context = Local<Context>::New (isolate, *priv->debug_context);
  Context::Scope context_scope (context);

  Debug::ProcessDebugMessages (isolate);
}

static GMainContext *
gum_v8_script_backend_get_main_context (GumScriptBackend * backend)
{
  return gum_script_scheduler_get_js_context (
      gum_v8_script_backend_get_scheduler (GUM_V8_SCRIPT_BACKEND (backend)));
}
