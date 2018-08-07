/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
#include <v8-inspector.h>

#define GUM_V8_SCRIPT_BACKEND_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_V8_SCRIPT_BACKEND_UNLOCK() (g_mutex_unlock (&self->mutex))

#define GUM_V8_SCRIPT_BACKEND_GET_PLATFORM(backend) \
    ((GumV8Platform *) gum_v8_script_backend_get_platform (backend))
#define GUM_V8_SCRIPT_BACKEND_GET_ISOLATE(backend) \
    ((Isolate *) gum_v8_script_backend_get_isolate (backend))

#define GUM_V8_FLAGS \
    "--es-staging " \
    "--harmony-do-expressions " \
    "--harmony-class-fields " \
    "--harmony-static-fields " \
    "--experimental-wasm-simd " \
    "--experimental-wasm-eh " \
    "--experimental-wasm-mv " \
    "--experimental-wasm-threads " \
    "--experimental-wasm-sat-f2i-conversions " \
    "--experimental-wasm-anyref " \
    "--expose-gc"

using namespace v8;
using namespace v8_inspector;

class GumInspectorClient;

template <typename T>
struct GumPersistent
{
  typedef Persistent<T, CopyablePersistentTraits<T> > type;
};

struct _GumV8ScriptBackend
{
  GObject parent;

  GMutex mutex;

  GumV8Platform * platform;

  GumScriptBackendDebugMessageHandler debug_handler;
  gpointer debug_handler_data;
  GDestroyNotify debug_handler_data_destroy;
  GMainContext * debug_handler_context;

  V8Inspector * inspector;
  GumInspectorClient * inspector_client;
};

struct GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

struct GumCreateScriptFromBytesData
{
  GBytes * bytes;
};

struct GumCompileScriptData
{
  gchar * name;
  gchar * source;
};

class GumInspectorClient : public V8InspectorClient
{
public:
  void runMessageLoopOnPause (int context_group_id) override;
  void quitMessageLoopOnPause () override;
  void runIfWaitingForDebugger (int context_group_id) override;
};

class GumInspectorChannel : public V8Inspector::Channel
{
public:
  void sendResponse (int call_id,
      std::unique_ptr<StringBuffer> message) override;
  void sendNotification (std::unique_ptr<StringBuffer> message) override;
  void flushProtocolNotifications () override;
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
    GBytes * bytes, GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static GumScript * gum_v8_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_v8_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, GBytes * bytes, GCancellable * cancellable,
    GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumV8ScriptBackend * backend, GBytes * bytes, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCreateScriptFromBytesData * d,
    GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_v8_script_backend_compile (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_v8_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumV8ScriptBackend * backend, const gchar * name, const gchar * source,
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
static void gum_v8_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);
static GumScriptScheduler * gum_v8_script_backend_get_scheduler_impl (
    GumScriptBackend * backend);

G_DEFINE_TYPE_EXTENDED (GumV8ScriptBackend,
                        gum_v8_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_v8_script_backend_iface_init))

static void
gum_v8_script_backend_class_init (GumV8ScriptBackendClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_script_backend_dispose;
  object_class->finalize = gum_v8_script_backend_finalize;
}

static void
gum_v8_script_backend_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  auto iface = (GumScriptBackendInterface *) g_iface;

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

  iface->get_scheduler = gum_v8_script_backend_get_scheduler_impl;
}

static void
gum_v8_script_backend_init (GumV8ScriptBackend * self)
{
  g_mutex_init (&self->mutex);

  self->platform = NULL;
}

static void
gum_v8_script_backend_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);

  g_clear_pointer (&self->debug_handler_context, g_main_context_unref);
  if (self->debug_handler_data_destroy != NULL)
    self->debug_handler_data_destroy (self->debug_handler_data);
  self->debug_handler = NULL;
  self->debug_handler_data = NULL;
  self->debug_handler_data_destroy = NULL;

  gum_v8_script_backend_disable_debugger (self);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->dispose (object);
}

static void
gum_v8_script_backend_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);

  delete self->platform;

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->finalize (object);
}

gpointer
gum_v8_script_backend_get_platform (GumV8ScriptBackend * self)
{
  if (self->platform == NULL)
  {
    V8::SetFlagsFromString (GUM_V8_FLAGS, (int) strlen (GUM_V8_FLAGS));
    self->platform = new GumV8Platform ();
    self->platform->GetIsolate ()->SetData (0, self);
  }

  return self->platform;
}

gpointer
gum_v8_script_backend_get_isolate (GumV8ScriptBackend * self)
{
  return GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetIsolate ();
}

GumScriptScheduler *
gum_v8_script_backend_get_scheduler (GumV8ScriptBackend * self)
{
  GumScriptScheduler * scheduler;

  scheduler = GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetScheduler ();

  gum_script_scheduler_start (scheduler);

  return scheduler;
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
                                         GBytes * bytes,
                                         GCancellable * cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, bytes, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_v8_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                GAsyncResult * result,
                                                GError ** error)
{
  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_v8_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                              GBytes * bytes,
                                              GCancellable * cancellable,
                                              GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, bytes, cancellable,
      NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumV8ScriptBackend * backend,
                                       GBytes * bytes,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  auto d = g_slice_new (GumCreateScriptFromBytesData);
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
  auto error = g_error_new (G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "not yet supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_create_script_from_bytes_data_free (GumCreateScriptFromBytesData * d)
{
  g_bytes_unref (d->bytes);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_v8_script_backend_compile (GumScriptBackend * backend,
                               const gchar * name,
                               const gchar * source,
                               GCancellable * cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_compile_script_task_new (self, name, source, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_v8_script_backend_compile_finish (GumScriptBackend * backend,
                                      GAsyncResult * result,
                                      GError ** error)
{
  return (GBytes *) gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result),
      error);
}

static GBytes *
gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
                                    const gchar * name,
                                    const gchar * source,
                                    GCancellable * cancellable,
                                    GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task =
      gum_compile_script_task_new (self, name, source, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto bytes = (GBytes *) gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumV8ScriptBackend * backend,
                             const gchar * name,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  auto d = g_slice_new (GumCompileScriptData);
  d->name = g_strdup (name);
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
  auto error = g_error_new (G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "not yet supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->name);
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

  if (self->debug_handler_data_destroy != NULL)
    self->debug_handler_data_destroy (self->debug_handler_data);

  self->debug_handler = handler;
  self->debug_handler_data = data;
  self->debug_handler_data_destroy = data_destroy;

  auto new_context = (handler != NULL)
      ? g_main_context_ref_thread_default ()
      : NULL;

  GUM_V8_SCRIPT_BACKEND_LOCK ();
  auto old_context = self->debug_handler_context;
  self->debug_handler_context = new_context;
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
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  auto client = new GumInspectorClient ();
  self->inspector_client = client;

  auto inspector = V8Inspector::create (isolate, client);
  self->inspector = inspector.release ();
}

static void
gum_v8_script_backend_disable_debugger (GumV8ScriptBackend * self)
{
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  delete self->inspector;
  self->inspector = nullptr;

  delete self->inspector_client;
  self->inspector_client = nullptr;
}

static void
gum_v8_script_backend_post_debug_message (GumScriptBackend * backend,
                                          const gchar * message)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->debug_handler == NULL)
    return;

  /* FIXME */
}

static GumScriptScheduler *
gum_v8_script_backend_get_scheduler_impl (GumScriptBackend * backend)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  return GUM_V8_SCRIPT_BACKEND_GET_PLATFORM (self)->GetScheduler ();
}

void
GumInspectorClient::runMessageLoopOnPause (int context_group_id)
{
  /* FIXME */
}

void
GumInspectorClient::quitMessageLoopOnPause ()
{
  /* FIXME */
}

void
GumInspectorClient::runIfWaitingForDebugger (int context_group_id)
{
  /* FIXME */
}

void
GumInspectorChannel::sendResponse (int call_id,
                                   std::unique_ptr<StringBuffer> message)
{
  /* FIXME */
}

void
GumInspectorChannel::sendNotification (std::unique_ptr<StringBuffer> message)
{
  /* FIXME */
}

void
GumInspectorChannel::flushProtocolNotifications ()
{
  /* FIXME */
}
