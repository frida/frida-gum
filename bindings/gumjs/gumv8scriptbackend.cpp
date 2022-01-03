/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8scriptbackend.h"

#include "gumscripttask.h"
#include "gumv8platform.h"
#include "gumv8script-priv.h"

#include <gum/guminterceptor.h>
#include <string.h>
#include <v8/v8-inspector.h>

#define GUM_V8_SCRIPT_BACKEND_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_V8_SCRIPT_BACKEND_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

#define GUM_V8_SCRIPT_BACKEND_GET_PLATFORM(backend) \
    ((GumV8Platform *) gum_v8_script_backend_get_platform (backend))
#define GUM_V8_SCRIPT_BACKEND_GET_ISOLATE(backend) \
    ((Isolate *) gum_v8_script_backend_get_isolate (backend))

#ifdef HAVE_IOS
# define GUM_V8_PLATFORM_FLAGS \
    "--write-protect-code-memory " \
    "--wasm-write-protect-code-memory "
#else
# define GUM_V8_PLATFORM_FLAGS
#endif

#define GUM_V8_FLAGS \
    GUM_V8_PLATFORM_FLAGS \
    "--use-strict " \
    "--expose-gc " \
    "--es-staging " \
    "--harmony-top-level-await " \
    "--wasm-staging " \
    "--experimental-wasm-eh " \
    "--experimental-wasm-simd " \
    "--experimental-wasm-return-call"

using namespace v8;
using namespace v8_inspector;

class GumInspectorClient;
class GumInspectorChannel;

typedef std::map<guint, std::unique_ptr<GumInspectorChannel>>
    GumInspectorChannelMap;

enum GumV8ScriptBackendState
{
  GUM_V8_BACKEND_RUNNING,
  GUM_V8_BACKEND_DEBUGGING,
  GUM_V8_BACKEND_PAUSED
};

struct _GumV8ScriptBackend
{
  GObject parent;

  GMutex mutex;
  GCond cond;
  volatile GumV8ScriptBackendState state;
  gboolean scope_mutex_trapped;

  GPtrArray * live_scripts;
  GumV8Platform * platform;
  int context_group_id;

  GumScriptBackendDebugMessageHandler debug_handler;
  gpointer debug_handler_data;
  GDestroyNotify debug_handler_data_destroy;
  GMainContext * debug_handler_context;
  GQueue debug_messages;
  volatile bool flush_scheduled;

  V8Inspector * inspector;
  GumInspectorClient * inspector_client;
  GumInspectorChannelMap * channels;
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

struct GumEmitDebugMessageData
{
  GumV8ScriptBackend * backend;
  gchar * message;
};

class GumInspectorClient : public V8InspectorClient
{
public:
  GumInspectorClient (GumV8ScriptBackend * backend);

  void runMessageLoopOnPause (int context_group_id) override;
  void quitMessageLoopOnPause () override;

  Local<Context> ensureDefaultContextInGroup (int contextGroupId) override;

  double currentTimeMS () override;

private:
  void startSkippingAllPauses ();

  GumV8ScriptBackend * backend;
};

class GumInspectorChannel : public V8Inspector::Channel
{
public:
  GumInspectorChannel (GumV8ScriptBackend * backend, guint id);

  void takeSession (std::unique_ptr<V8InspectorSession> session);
  void dispatchStanza (const char * stanza);
  void startSkippingAllPauses ();

  void sendResponse (int call_id,
      std::unique_ptr<StringBuffer> message) override;
  void sendNotification (std::unique_ptr<StringBuffer> message) override;
  void flushProtocolNotifications () override;

private:
  void emitStanza (std::unique_ptr<StringBuffer> stanza);

  GumV8ScriptBackend * backend;
  guint id;
  std::unique_ptr<V8InspectorSession> inspector_session;
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

static void gum_v8_script_backend_on_context_created (GumV8ScriptBackend * self,
    Local<Context> * context, GumV8Script * script);
static void gum_v8_script_backend_on_context_destroyed (
    GumV8ScriptBackend * self, Local<Context> * context, GumV8Script * script);

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
static void gum_v8_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);
static void gum_v8_script_backend_process_queued_debug_messages (
    GumV8ScriptBackend * self);
static void gum_v8_script_backend_process_queued_debug_messages_unlocked (
    GumV8ScriptBackend * self);
static void gum_v8_script_backend_drop_queued_debug_messages_unlocked (
    GumV8ScriptBackend * self);
static void gum_v8_script_backend_process_debug_message (
    GumV8ScriptBackend * self, const gchar * message);
static gboolean gum_v8_script_backend_do_emit_debug_message (
    GumEmitDebugMessageData * d);
static void gum_emit_debug_message_data_free (GumEmitDebugMessageData * d);

static void gum_v8_script_backend_with_lock_held (GumScriptBackend * backend,
    GumScriptBackendLockedFunc func, gpointer user_data);
static gboolean gum_v8_script_backend_is_locked (GumScriptBackend * backend);

static void gum_v8_script_backend_clear_inspector_channels (
    GumV8ScriptBackend * self);
static void gum_v8_script_backend_notify_context_created (
    GumV8ScriptBackend * self, Local<Context> * context, GumV8Script * script);
static void gum_v8_script_backend_notify_context_destroyed (
    GumV8ScriptBackend * self, Local<Context> * context, GumV8Script * script);
static void gum_v8_script_backend_connect_inspector_channel (
    GumV8ScriptBackend * self, guint id);
static void gum_v8_script_backend_disconnect_inspector_channel (
    GumV8ScriptBackend * self, guint id);
static void gum_v8_script_backend_dispatch_inspector_stanza (
    GumV8ScriptBackend * self, guint channel_id, const gchar * stanza);

static std::unique_ptr<StringBuffer> gum_string_buffer_from_utf8 (
    const gchar * str);
static gchar * gum_string_view_to_utf8 (const StringView & view);

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

  iface->with_lock_held = gum_v8_script_backend_with_lock_held;
  iface->is_locked = gum_v8_script_backend_is_locked;
}

static void
gum_v8_script_backend_init (GumV8ScriptBackend * self)
{
  g_mutex_init (&self->mutex);
  g_cond_init (&self->cond);
  self->state = GUM_V8_BACKEND_RUNNING;
  self->scope_mutex_trapped = FALSE;

  self->live_scripts = g_ptr_array_sized_new (1);
  self->platform = NULL;
  self->context_group_id = 1;

  g_queue_init (&self->debug_messages);
  self->flush_scheduled = false;

  self->channels = new GumInspectorChannelMap ();
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

  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  self->state = GUM_V8_BACKEND_RUNNING;
  g_cond_signal (&self->cond);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  gum_v8_script_backend_clear_inspector_channels (self);

  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  gum_v8_script_backend_drop_queued_debug_messages_unlocked (self);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

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

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->dispose (object);
}

static void
gum_v8_script_backend_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);

  delete self->channels;

  delete self->platform;
  g_ptr_array_free (self->live_scripts, TRUE);

  g_cond_clear (&self->cond);
  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->finalize (object);
}

gpointer
gum_v8_script_backend_get_platform (GumV8ScriptBackend * self)
{
  if (self->platform == NULL)
  {
    GString * flags;

    flags = g_string_new (GUM_V8_FLAGS);

    if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
    {
      g_string_append (flags, " --jitless");
    }

    V8::SetFlagsFromString (flags->str, (size_t) flags->len);

    g_string_free (flags, TRUE);

    self->platform = new GumV8Platform ();
    self->platform->GetIsolate ()->SetData (0, self);

    auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    auto client = new GumInspectorClient (self);
    self->inspector_client = client;

    auto inspector = V8Inspector::create (isolate, client);
    self->inspector = inspector.release ();
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
  g_signal_connect_swapped (script, "context-created",
      G_CALLBACK (gum_v8_script_backend_on_context_created), self);
  g_signal_connect_swapped (script, "context-destroyed",
      G_CALLBACK (gum_v8_script_backend_on_context_destroyed), self);

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
  auto error = g_error_new (GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
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
gum_v8_script_backend_on_context_created (GumV8ScriptBackend * self,
                                          Local<Context> * context,
                                          GumV8Script * script)
{
  gum_v8_script_backend_notify_context_created (self, context, script);
}

static void
gum_v8_script_backend_on_context_destroyed (GumV8ScriptBackend * self,
                                            Local<Context> * context,
                                            GumV8Script * script)
{
  gum_v8_script_backend_notify_context_destroyed (self, context, script);
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
  auto error = g_error_new (GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
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

  GUM_V8_SCRIPT_BACKEND_LOCK (self);

  auto old_context = self->debug_handler_context;
  self->debug_handler_context = new_context;

  if (handler != NULL)
  {
    if (self->state == GUM_V8_BACKEND_RUNNING)
      self->state = GUM_V8_BACKEND_DEBUGGING;
  }
  else
  {
    gum_v8_script_backend_drop_queued_debug_messages_unlocked (self);

    self->state = GUM_V8_BACKEND_RUNNING;
    g_cond_signal (&self->cond);
  }

  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  if (old_context != NULL)
    g_main_context_unref (old_context);

  if (handler == NULL)
  {
    gum_script_scheduler_push_job_on_js_thread (
        gum_v8_script_backend_get_scheduler (self), G_PRIORITY_DEFAULT,
        (GumScriptJobFunc) gum_v8_script_backend_clear_inspector_channels,
        self, NULL);
  }
}

static void
gum_v8_script_backend_post_debug_message (GumScriptBackend * backend,
                                          const gchar * message)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->debug_handler == NULL)
    return;

  gchar * message_copy = g_strdup (message);

  GUM_V8_SCRIPT_BACKEND_LOCK (self);

  g_queue_push_tail (&self->debug_messages, message_copy);
  g_cond_signal (&self->cond);

  bool flush_not_already_scheduled = !self->flush_scheduled;
  self->flush_scheduled = true;

  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  if (flush_not_already_scheduled)
  {
    gum_script_scheduler_push_job_on_js_thread (
        gum_v8_script_backend_get_scheduler (self), G_PRIORITY_DEFAULT,
        (GumScriptJobFunc) gum_v8_script_backend_process_queued_debug_messages,
        self, NULL);
  }
}

static void
gum_v8_script_backend_process_queued_debug_messages (GumV8ScriptBackend * self)
{
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  gum_v8_script_backend_process_queued_debug_messages_unlocked (self);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  isolate->PerformMicrotaskCheckpoint ();
}

static void
gum_v8_script_backend_process_queued_debug_messages_unlocked (
    GumV8ScriptBackend * self)
{
  gchar * message;
  while ((message = (gchar *) g_queue_pop_head (&self->debug_messages)) != NULL)
  {
    GUM_V8_SCRIPT_BACKEND_UNLOCK (self);
    gum_v8_script_backend_process_debug_message (self, message);
    GUM_V8_SCRIPT_BACKEND_LOCK (self);

    g_free (message);
  }

  self->flush_scheduled = false;
}

static void
gum_v8_script_backend_drop_queued_debug_messages_unlocked (
    GumV8ScriptBackend * self)
{
  gchar * message;
  while ((message = (gchar *) g_queue_pop_head (&self->debug_messages)) != NULL)
    g_free (message);
}

static void
gum_v8_script_backend_process_debug_message (GumV8ScriptBackend * self,
                                             const gchar * message)
{
  guint id;
  const char * id_start, * id_end;
  id_start = strchr (message, ' ');
  if (id_start == NULL)
    return;
  id_start++;
  id = (guint) g_ascii_strtoull (id_start, (gchar **) &id_end, 10);
  if (id_end == id_start)
    return;

  if (g_str_has_prefix (message, "CONNECT "))
  {
    gum_v8_script_backend_connect_inspector_channel (self, id);
  }
  else if (g_str_has_prefix (message, "DISCONNECT "))
  {
    gum_v8_script_backend_disconnect_inspector_channel (self, id);
  }
  else if (g_str_has_prefix (message, "DISPATCH "))
  {
    if (*id_end != ' ')
      return;
    const char * stanza = id_end + 1;
    gum_v8_script_backend_dispatch_inspector_stanza (self, id, stanza);
  }
}

static void
gum_v8_script_backend_emit_debug_message (GumV8ScriptBackend * self,
                                          const gchar * format,
                                          ...)
{
  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  auto context = (self->debug_handler_context != NULL)
      ? g_main_context_ref (self->debug_handler_context)
      : NULL;
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  if (context == NULL)
    return;

  auto d = g_slice_new (GumEmitDebugMessageData);

  d->backend = self;
  g_object_ref (self);

  va_list args;
  va_start (args, format);
  d->message = g_strdup_vprintf (format, args);
  va_end (args);

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
  auto self = d->backend;

  if (self->debug_handler != NULL)
    self->debug_handler (d->message, self->debug_handler_data);

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
gum_v8_script_backend_with_lock_held (GumScriptBackend * backend,
                                      GumScriptBackendLockedFunc func,
                                      gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
  {
    func (user_data);
    return;
  }

  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  {
    Locker locker (isolate);

    func (user_data);
  }
}

static gboolean
gum_v8_script_backend_is_locked (GumScriptBackend * backend)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
    return FALSE;

  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  if (Locker::IsLocked (isolate))
    return FALSE;

  return Locker::IsLockedByAnyThread (isolate);
}

gboolean
gum_v8_script_backend_is_scope_mutex_trapped (GumV8ScriptBackend * self)
{
  return self->scope_mutex_trapped;
}

void
gum_v8_script_backend_mark_scope_mutex_trapped (GumV8ScriptBackend * self)
{
  self->scope_mutex_trapped = TRUE;
}

static void
gum_v8_script_backend_clear_inspector_channels (GumV8ScriptBackend * self)
{
  auto isolate = GUM_V8_SCRIPT_BACKEND_GET_ISOLATE (self);

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  bool debugger_still_disabled = (self->state == GUM_V8_BACKEND_RUNNING);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  if (debugger_still_disabled)
    self->channels->clear ();
}

static void
gum_v8_script_backend_notify_context_created (GumV8ScriptBackend * self,
                                              Local<Context> * context,
                                              GumV8Script * script)
{
  g_ptr_array_add (self->live_scripts, script);

  auto name_buffer = gum_string_buffer_from_utf8 (script->name);
  V8ContextInfo info (*context, self->context_group_id, name_buffer->string ());

  self->inspector->contextCreated (info);
}

static void
gum_v8_script_backend_notify_context_destroyed (GumV8ScriptBackend * self,
                                                Local<Context> * context,
                                                GumV8Script * script)
{
  self->inspector->contextDestroyed (*context);

  g_ptr_array_remove (self->live_scripts, script);
}

static void
gum_v8_script_backend_connect_inspector_channel (GumV8ScriptBackend * self,
                                                 guint id)
{
  auto channel = new GumInspectorChannel (self, id);
  (*self->channels)[id] = std::unique_ptr<GumInspectorChannel> (channel);

  auto session = self->inspector->connect (self->context_group_id, channel,
      StringView ());
  channel->takeSession (std::move (session));
}

static void
gum_v8_script_backend_disconnect_inspector_channel (GumV8ScriptBackend * self,
                                                    guint id)
{
  self->channels->erase (id);
}

static void
gum_v8_script_backend_dispatch_inspector_stanza (GumV8ScriptBackend * self,
                                                 guint channel_id,
                                                 const gchar * stanza)
{
  auto channel = (*self->channels)[channel_id].get ();
  if (channel == nullptr)
    return;

  channel->dispatchStanza (stanza);
}

static void
gum_v8_script_backend_emit_inspector_stanza (GumV8ScriptBackend * self,
                                             guint channel_id,
                                             const gchar * stanza)
{
  gum_v8_script_backend_emit_debug_message (self, "DISPATCH %u %s",
      channel_id, stanza);
}

GumInspectorClient::GumInspectorClient (GumV8ScriptBackend * backend)
  : backend (backend)
{
}

void
GumInspectorClient::runMessageLoopOnPause (int context_group_id)
{
  GUM_V8_SCRIPT_BACKEND_LOCK (backend);

  if (backend->state == GUM_V8_BACKEND_RUNNING)
  {
    startSkippingAllPauses ();
    GUM_V8_SCRIPT_BACKEND_UNLOCK (backend);
    return;
  }

  backend->state = GUM_V8_BACKEND_PAUSED;
  while (backend->state == GUM_V8_BACKEND_PAUSED)
  {
    gum_v8_script_backend_process_queued_debug_messages_unlocked (backend);

    if (backend->state == GUM_V8_BACKEND_PAUSED)
      g_cond_wait (&backend->cond, &backend->mutex);
  }

  gum_v8_script_backend_process_queued_debug_messages_unlocked (backend);

  if (backend->state == GUM_V8_BACKEND_RUNNING)
  {
    startSkippingAllPauses ();
  }

  GUM_V8_SCRIPT_BACKEND_UNLOCK (backend);
}

void
GumInspectorClient::quitMessageLoopOnPause ()
{
  GUM_V8_SCRIPT_BACKEND_LOCK (backend);

  if (backend->state == GUM_V8_BACKEND_PAUSED)
  {
    backend->state = GUM_V8_BACKEND_DEBUGGING;
    g_cond_signal (&backend->cond);
  }

  GUM_V8_SCRIPT_BACKEND_UNLOCK (backend);
}

Local<Context>
GumInspectorClient::ensureDefaultContextInGroup (int contextGroupId)
{
  GPtrArray * live_scripts = backend->live_scripts;

  if (live_scripts->len == 0)
    return Local<Context> ();

  GumV8Script * script = GUM_V8_SCRIPT (g_ptr_array_index (live_scripts, 0));
  return Local<Context>::New (script->isolate, *script->context);
}

double
GumInspectorClient::currentTimeMS ()
{
  return backend->platform->CurrentClockTimeMillis ();
}

void
GumInspectorClient::startSkippingAllPauses ()
{
  for (const auto & pair : *backend->channels)
  {
    pair.second->startSkippingAllPauses ();
  }
}

GumInspectorChannel::GumInspectorChannel (GumV8ScriptBackend * backend,
                                          guint id)
  : backend (backend),
    id (id)
{
}

void
GumInspectorChannel::takeSession (std::unique_ptr<V8InspectorSession> session)
{
  inspector_session = std::move (session);
}

void
GumInspectorChannel::dispatchStanza (const char * stanza)
{
  auto buffer = gum_string_buffer_from_utf8 (stanza);

  inspector_session->dispatchProtocolMessage (buffer->string ());
}

void
GumInspectorChannel::startSkippingAllPauses ()
{
  inspector_session->setSkipAllPauses (true);
}

void
GumInspectorChannel::emitStanza (std::unique_ptr<StringBuffer> stanza)
{
  gchar * stanza_utf8 = gum_string_view_to_utf8 (stanza->string ());

  gum_v8_script_backend_emit_inspector_stanza (backend, id, stanza_utf8);

  g_free (stanza_utf8);
}

void
GumInspectorChannel::sendResponse (int call_id,
                                   std::unique_ptr<StringBuffer> message)
{
  emitStanza (std::move (message));
}

void
GumInspectorChannel::sendNotification (std::unique_ptr<StringBuffer> message)
{
  emitStanza (std::move (message));
}

void
GumInspectorChannel::flushProtocolNotifications ()
{
}

static std::unique_ptr<StringBuffer>
gum_string_buffer_from_utf8 (const gchar * str)
{
  glong length;
  auto str_utf16 = g_utf8_to_utf16 (str, -1, NULL, &length, NULL);
  g_assert (str_utf16 != NULL);

  auto buffer = StringBuffer::create (StringView (str_utf16, length));

  g_free (str_utf16);

  return buffer;
}

static gchar *
gum_string_view_to_utf8 (const StringView & view)
{
  if (view.is8Bit ())
    return g_strndup ((const gchar *) view.characters8 (), view.length ());

  return g_utf16_to_utf8 (view.characters16 (), (glong) view.length (), NULL,
      NULL, NULL);
}
