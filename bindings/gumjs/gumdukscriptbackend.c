/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukscriptbackend.h"

#include "duktape.h"
#include "gumdukscript.h"
#include "gumscripttask.h"

#include <gum/guminterceptor.h>

#define GUM_DUK_SCRIPT_BACKEND_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_DUK_SCRIPT_BACKEND_UNLOCK() (g_mutex_unlock (&priv->mutex))

typedef guint GumDukScriptId;
typedef struct _GumDukScriptWeakRef GumDukScriptWeakRef;
typedef struct _GumCreateScriptData GumCreateScriptData;
typedef struct _GumCreateScriptFromBytesData GumCreateScriptFromBytesData;
typedef struct _GumCompileScriptData GumCompileScriptData;
typedef struct _GumNotifyScriptAddedData GumNotifyScriptAddedData;
typedef struct _GumNotifyScriptRemovedData GumNotifyScriptRemovedData;
typedef struct _GumNotifyDebuggerDetachedData GumNotifyDebuggerDetachedData;
typedef struct _GumNotifyDebuggerOutputData GumNotifyDebuggerOutputData;

struct _GumDukScriptBackendPrivate
{
  GMutex mutex;
  GHashTable * scripts;
  GumDukScriptId next_script_id;

  GumScriptScheduler * scheduler;

  GumScriptBackendDebugMessageHandler debug_handler;
  gpointer debug_handler_data;
  GDestroyNotify debug_handler_data_destroy;
  GMainContext * debug_handler_context;
  GHashTable * debug_handler_announced_scripts;
};

struct _GumDukScriptWeakRef
{
  GumDukScriptBackend * backend;
  GumDukScriptId id;
  GWeakRef instance;
};

struct _GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

struct _GumCreateScriptFromBytesData
{
  gchar * name;
  GBytes * bytes;
};

struct _GumCompileScriptData
{
  gchar * source;
};

struct _GumNotifyScriptAddedData
{
  GumDukScriptBackend * backend;
  GumDukScriptId id;
  gchar * name;
};

struct _GumNotifyScriptRemovedData
{
  GumDukScriptBackend * backend;
  GumDukScriptId id;
};

struct _GumNotifyDebuggerDetachedData
{
  GumDukScriptBackend * backend;
  GumDukScriptId id;
};

struct _GumNotifyDebuggerOutputData
{
  GumDukScriptBackend * backend;
  GumDukScriptId id;
  GBytes * bytes;
};

static void gum_duk_script_backend_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_script_backend_dispose (GObject * object);
static void gum_duk_script_backend_finalize (GObject * object);

static void gum_duk_script_weak_ref_on_notify (GumDukScriptWeakRef * ref,
    GObject * where_the_object_was);

static void gum_duk_script_backend_create (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_duk_script_backend_create_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_duk_script_backend_create_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_task_new (
    GumDukScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_task_run (GumScriptTask * task,
    GumDukScriptBackend * self, GumCreateScriptData * d,
    GCancellable * cancellable);
static void gum_create_script_data_free (GumCreateScriptData * d);
static void gum_duk_script_backend_create_from_bytes (
    GumScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static GumScript * gum_duk_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_duk_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumDukScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    GumDukScriptBackend * self, GumCreateScriptFromBytesData * d,
    GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_duk_script_backend_compile (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_duk_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_duk_script_backend_compile_sync (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumDukScriptBackend * backend, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_compile_script_task_run (GumScriptTask * task,
    GumDukScriptBackend * self, GumCompileScriptData * d,
    GCancellable * cancellable);
static void gum_compile_script_data_free (GumCompileScriptData * d);

static void gum_duk_script_backend_set_debug_message_handler (
    GumScriptBackend * backend, GumScriptBackendDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
static void gum_duk_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);
static GMainContext * gum_duk_script_backend_get_main_context (
    GumScriptBackend * backend);
static void gum_duk_script_backend_on_debug_handler_attached (
    GumDukScriptBackend * self);
static void gum_duk_script_backend_on_debug_handler_detached (
    GumDukScriptBackend * self);
static void gum_duk_script_backend_on_script_added (GumDukScriptBackend * self,
    GumDukScriptId id, GumDukScript * script);
static gboolean gum_duk_script_backend_notify_script_added (
    GumNotifyScriptAddedData * d);
static void gum_notify_script_added_data_free (GumNotifyScriptAddedData * d);
static void gum_duk_script_backend_on_script_removed (
    GumDukScriptBackend * self, GumDukScriptId id);
static gboolean gum_duk_script_backend_notify_script_removed (
    GumNotifyScriptRemovedData * d);
static void gum_notify_script_removed_data_free (
    GumNotifyScriptRemovedData * d);
static void gum_duk_script_backend_on_debugger_detached (GumDukScript * script,
    GumDukScriptWeakRef * ref);
static gboolean gum_duk_script_backend_notify_debugger_detached (
    GumNotifyDebuggerDetachedData * d);
static void gum_notify_debugger_detached_data_free (
    GumNotifyDebuggerDetachedData * d);
static void gum_duk_script_backend_on_debugger_output (GumDukScript * script,
    GBytes * bytes, GumDukScriptWeakRef * ref);
static gboolean gum_duk_script_backend_notify_debugger_output (
    GumNotifyDebuggerOutputData * d);
static void gum_notify_debugger_output_data_free (
    GumNotifyDebuggerOutputData * d);

static void gum_duk_script_backend_on_fatal_error (void * udata,
    const char * msg);

static void * gum_duk_alloc (void * udata, duk_size_t size);
static void * gum_duk_realloc (void * udata, void * ptr, duk_size_t size);
static void gum_duk_free (void * udata, void * ptr);

G_DEFINE_TYPE_EXTENDED (GumDukScriptBackend,
                        gum_duk_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_duk_script_backend_iface_init));

static void
gum_duk_script_backend_class_init (GumDukScriptBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumDukScriptBackendPrivate));

  object_class->dispose = gum_duk_script_backend_dispose;
  object_class->finalize = gum_duk_script_backend_finalize;
}

static void
gum_duk_script_backend_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumScriptBackendIface * iface = (GumScriptBackendIface *) g_iface;

  (void) iface_data;

  iface->create = gum_duk_script_backend_create;
  iface->create_finish = gum_duk_script_backend_create_finish;
  iface->create_sync = gum_duk_script_backend_create_sync;
  iface->create_from_bytes = gum_duk_script_backend_create_from_bytes;
  iface->create_from_bytes_finish =
      gum_duk_script_backend_create_from_bytes_finish;
  iface->create_from_bytes_sync = gum_duk_script_backend_create_from_bytes_sync;

  iface->compile = gum_duk_script_backend_compile;
  iface->compile_finish = gum_duk_script_backend_compile_finish;
  iface->compile_sync = gum_duk_script_backend_compile_sync;

  iface->set_debug_message_handler =
      gum_duk_script_backend_set_debug_message_handler;
  iface->post_debug_message = gum_duk_script_backend_post_debug_message;

  iface->get_main_context = gum_duk_script_backend_get_main_context;
}

static void
gum_duk_script_backend_init (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackendPrivate);

  g_mutex_init (&priv->mutex);

  priv->scripts = g_hash_table_new (NULL, NULL);
  priv->next_script_id = 1;

  priv->scheduler = NULL;

  priv->debug_handler_announced_scripts = g_hash_table_new (NULL, NULL);
}

static void
gum_duk_script_backend_dispose (GObject * object)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (object);
  GumDukScriptBackendPrivate * priv = self->priv;

  g_clear_pointer (&priv->debug_handler_announced_scripts, g_hash_table_unref);
  g_clear_pointer (&priv->debug_handler_context, g_main_context_unref);
  if (priv->debug_handler_data_destroy != NULL)
    priv->debug_handler_data_destroy (priv->debug_handler_data);
  priv->debug_handler = NULL;
  priv->debug_handler_data = NULL;
  priv->debug_handler_data_destroy = NULL;

  g_clear_object (&priv->scheduler);

  g_clear_pointer (&priv->scripts, g_hash_table_unref);

  G_OBJECT_CLASS (gum_duk_script_backend_parent_class)->dispose (object);
}

static void
gum_duk_script_backend_finalize (GObject * object)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (object);

  g_mutex_clear (&self->priv->mutex);

  G_OBJECT_CLASS (gum_duk_script_backend_parent_class)->finalize (object);
}

static void
gum_duk_script_backend_add (GumDukScriptBackend * self,
                            GumDukScript * script)
{
  GumDukScriptBackendPrivate * priv = self->priv;
  GumDukScriptWeakRef * ref;

  ref = g_slice_new (GumDukScriptWeakRef);
  ref->backend = self;
  do
  {
    ref->id = priv->next_script_id++;
  }
  while (ref->id == 0);
  g_weak_ref_init (&ref->instance, script);

  GUM_DUK_SCRIPT_BACKEND_LOCK ();
  g_hash_table_insert (priv->scripts, GSIZE_TO_POINTER (ref->id), ref);
  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  g_object_weak_ref (G_OBJECT (script),
      (GWeakNotify) gum_duk_script_weak_ref_on_notify, ref);

  g_signal_connect (script, "debugger-detached",
      G_CALLBACK (gum_duk_script_backend_on_debugger_detached), ref);
  g_signal_connect (script, "debugger-output",
      G_CALLBACK (gum_duk_script_backend_on_debugger_output), ref);

  gum_duk_script_backend_on_script_added (self, ref->id, script);
}

static void
gum_duk_script_weak_ref_on_notify (GumDukScriptWeakRef * ref,
                                   GObject * where_the_object_was)
{
  GumDukScriptBackendPrivate * priv = ref->backend->priv;

  (void) where_the_object_was;

  gum_duk_script_backend_on_script_removed (ref->backend, ref->id);

  GUM_DUK_SCRIPT_BACKEND_LOCK ();
  g_hash_table_remove (priv->scripts, GSIZE_TO_POINTER (ref->id));
  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  g_weak_ref_clear (&ref->instance);

  g_slice_free (GumDukScriptWeakRef, ref);
}

gpointer
gum_duk_script_backend_create_heap (GumDukScriptBackend * self)
{
  (void) self;

  return duk_create_heap (gum_duk_alloc, gum_duk_realloc, gum_duk_free, self,
      gum_duk_script_backend_on_fatal_error);
}

gboolean
gum_duk_script_backend_push_program (GumDukScriptBackend * self,
                                     gpointer ctx,
                                     const gchar * name,
                                     const gchar * source,
                                     GError ** error)
{
  gchar * url;
  gboolean valid;

  (void) self;

  url = g_strconcat (name, ".js", NULL);

  duk_push_string (ctx, source);
  duk_push_string (ctx, url);
  valid = duk_pcompile (ctx, 0) == 0;

  g_free (url);

  if (!valid)
  {
    gchar message[1024];
    gint line;

    /*
     * As duktape doesn't currently provide line number information, we
     * grab it from the error message itself using an sscanf.
     */
    sscanf (duk_safe_to_string (ctx, -1), "%[^\n(] (line %d)", message, &line);

    duk_pop (ctx);

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message);
  }

  return valid;
}

GumScriptScheduler *
gum_duk_script_backend_get_scheduler (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv = self->priv;

  if (priv->scheduler == NULL)
    priv->scheduler = gum_script_scheduler_new ();

  return priv->scheduler;
}

static void
gum_duk_script_backend_create (GumScriptBackend * backend,
                               const gchar * name,
                               const gchar * source,
                               GCancellable * cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_duk_script_backend_create_finish (GumScriptBackend * backend,
                                      GAsyncResult * result,
                                      GError ** error)
{
  (void) backend;

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GumScript *
gum_duk_script_backend_create_sync (GumScriptBackend * backend,
                                    const gchar * name,
                                    const gchar * source,
                                    GCancellable * cancellable,
                                    GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  script = gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_task_new (GumDukScriptBackend * backend,
                            const gchar * name,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  GumCreateScriptData * d;
  GumScriptTask * task;

  d = g_slice_new (GumCreateScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  task = gum_script_task_new ((GumScriptTaskFunc) gum_create_script_task_run,
      backend, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_data_free);
  return task;
}

static void
gum_create_script_task_run (GumScriptTask * task,
                            GumDukScriptBackend * self,
                            GumCreateScriptData * d,
                            GCancellable * cancellable)
{
  GumDukScript * script;
  GError * error = NULL;

  (void) cancellable;

  script = g_object_new (GUM_DUK_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

  gum_duk_script_create_context (script, &error);

  if (error == NULL)
  {
    gum_duk_script_backend_add (self, script);

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
gum_duk_script_backend_create_from_bytes (GumScriptBackend * backend,
                                          const gchar * name,
                                          GBytes * bytes,
                                          GCancellable * cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, name, bytes, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_duk_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                 GAsyncResult * result,
                                                 GError ** error)
{
  (void) backend;

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GumScript *
gum_duk_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                               const gchar * name,
                                               GBytes * bytes,
                                               GCancellable * cancellable,
                                               GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, name, bytes, cancellable,
      NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumDukScriptBackend * backend,
                                       const gchar * name,
                                       GBytes * bytes,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  GumCreateScriptFromBytesData * d;
  GumScriptTask * task;

  d = g_slice_new (GumCreateScriptFromBytesData);
  d->name = g_strdup (name);
  d->bytes = g_bytes_ref (bytes);

  task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_from_bytes_task_run, backend,
      cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_from_bytes_data_free);
  return task;
}

static void
gum_create_script_from_bytes_task_run (GumScriptTask * task,
                                       GumDukScriptBackend * self,
                                       GumCreateScriptFromBytesData * d,
                                       GCancellable * cancellable)
{
  GumDukScript * script;
  GError * error = NULL;

  (void) cancellable;

  script = g_object_new (GUM_DUK_TYPE_SCRIPT,
      "name", d->name,
      "bytecode", d->bytes,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

  gum_duk_script_create_context (script, &error);

  if (error == NULL)
  {
    gum_duk_script_backend_add (self, script);

    gum_script_task_return_pointer (task, script, g_object_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);
    g_object_unref (script);
  }
}

static void
gum_create_script_from_bytes_data_free (GumCreateScriptFromBytesData * d)
{
  g_free (d->name);
  g_bytes_unref (d->bytes);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_duk_script_backend_compile (GumScriptBackend * backend,
                                const gchar * source,
                                GCancellable * cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_duk_script_backend_compile_finish (GumScriptBackend * backend,
                                       GAsyncResult * result,
                                       GError ** error)
{
  (void) backend;

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GBytes *
gum_duk_script_backend_compile_sync (GumScriptBackend * backend,
                                     const gchar * source,
                                     GCancellable * cancellable,
                                     GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GBytes * bytes;
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, source, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  bytes = gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumDukScriptBackend * backend,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  GumCompileScriptData * d = g_slice_new (GumCompileScriptData);
  d->source = g_strdup (source);

  GumScriptTask * task = gum_script_task_new (
      (GumScriptTaskFunc) gum_compile_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_compile_script_data_free);
  return task;
}

static void
gum_compile_script_task_run (GumScriptTask * task,
                             GumDukScriptBackend * self,
                             GumCompileScriptData * d,
                             GCancellable * cancellable)
{
  duk_context * ctx;
  GError * error = NULL;

  (void) cancellable;

  ctx = gum_duk_script_backend_create_heap (self);

  gum_duk_script_backend_push_program (self, ctx, "agent", d->source, &error);

  if (error == NULL)
  {
    gconstpointer code;
    duk_size_t size;
    GBytes * bytes;

    duk_dump_function (ctx);

    code = duk_require_buffer_data (ctx, -1, &size);

    bytes = g_bytes_new_with_free_func (code, size,
        (GDestroyNotify) duk_destroy_heap, ctx);

    gum_script_task_return_pointer (task, bytes,
        (GDestroyNotify) g_bytes_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);

    duk_destroy_heap (ctx);
  }
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->source);

  g_slice_free (GumCompileScriptData, d);
}

static void
gum_duk_script_backend_set_debug_message_handler (
    GumScriptBackend * backend,
    GumScriptBackendDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumDukScriptBackendPrivate * priv = self->priv;
  GMainContext * new_context, * old_context;

  if (priv->debug_handler_data_destroy != NULL)
    priv->debug_handler_data_destroy (priv->debug_handler_data);

  priv->debug_handler = handler;
  priv->debug_handler_data = data;
  priv->debug_handler_data_destroy = data_destroy;

  new_context = (handler != NULL)
      ? g_main_context_ref_thread_default ()
      : NULL;
  GUM_DUK_SCRIPT_BACKEND_LOCK ();
  old_context = priv->debug_handler_context;
  priv->debug_handler_context = new_context;
  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  if (old_context != NULL)
    g_main_context_unref (old_context);

  if (handler != NULL)
    gum_duk_script_backend_on_debug_handler_attached (self);
  else
    gum_duk_script_backend_on_debug_handler_detached (self);
}

static GMainContext *
gum_duk_script_backend_get_debug_context (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv = self->priv;
  GMainContext * context;

  GUM_DUK_SCRIPT_BACKEND_LOCK ();
  context = (priv->debug_handler_context != NULL)
      ? g_main_context_ref (priv->debug_handler_context)
      : NULL;
  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  return context;
}

static void
gum_duk_script_backend_post_debug_message (GumScriptBackend * backend,
                                           const gchar * message)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumDukScriptBackendPrivate * priv = self->priv;
  const gchar * id_start, * id_end;
  GumDukScriptId id;
  GumDukScriptWeakRef * ref;
  GumDukScript * script = NULL;

  id_start = strchr (message, ' ');
  if (id_start == NULL)
    return;
  id_start++;

  id = (GumDukScriptId) g_ascii_strtoull (id_start, (gchar **) &id_end, 10);
  if (id_end == id_start)
    return;

  GUM_DUK_SCRIPT_BACKEND_LOCK ();
  ref = g_hash_table_lookup (priv->scripts, GSIZE_TO_POINTER (id));
  script = (ref != NULL) ? g_weak_ref_get (&ref->instance) : NULL;
  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  if (script == NULL)
    return;

  if (g_str_has_prefix (message, "POST "))
  {
    guchar * data;
    gsize size;
    GBytes * bytes;

    if (*id_end != ' ')
      return;

    data = g_base64_decode (id_end + 1, &size);
    bytes = g_bytes_new_take (data, size);

    gum_duk_script_post_to_debugger (script, bytes);
  }
  else if (g_str_has_prefix (message, "ATTACH "))
  {
    gum_duk_script_attach_debugger (script);
  }
  else if (g_str_has_prefix (message, "DETACH "))
  {
    gum_duk_script_detach_debugger (script);
  }

  g_object_unref (script);
}

static GMainContext *
gum_duk_script_backend_get_main_context (GumScriptBackend * backend)
{
  return gum_script_scheduler_get_js_context (
      gum_duk_script_backend_get_scheduler (GUM_DUK_SCRIPT_BACKEND (backend)));
}

static void
gum_duk_script_backend_on_debug_handler_attached (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv = self->priv;
  GString * message;
  GHashTableIter iter;
  gpointer raw_id;
  GumDukScriptWeakRef * ref;
  guint script_index;

  g_hash_table_remove_all (priv->debug_handler_announced_scripts);

  message = g_string_sized_new (64);
  g_string_append (message, "SYNC\n");

  GUM_DUK_SCRIPT_BACKEND_LOCK ();

  g_hash_table_iter_init (&iter, priv->scripts);
  script_index = 0;

  while (g_hash_table_iter_next (&iter, &raw_id, (gpointer *) &ref))
  {
    GumDukScriptId id = GPOINTER_TO_SIZE (raw_id);
    GumDukScript * script;
    gchar * name, * name_escaped;

    script = g_weak_ref_get (&ref->instance);
    if (script == NULL)
      continue;
    g_object_get (script, "name", &name, NULL);
    name_escaped = g_strescape (name, NULL);

    if (script_index != 0)
      g_string_append_c (message, '\n');

    g_string_append_printf (message, "%u %s.js", id, name_escaped);

    g_free (name_escaped);
    g_free (name);
    g_object_unref (script);

    g_hash_table_insert (priv->debug_handler_announced_scripts, raw_id, raw_id);

    script_index++;
  }

  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();

  priv->debug_handler (message->str, priv->debug_handler_data);

  g_string_free (message, TRUE);
}

static void
gum_duk_script_backend_on_debug_handler_detached (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv = self->priv;
  GHashTableIter iter;
  GumDukScriptWeakRef * ref;

  g_hash_table_remove_all (priv->debug_handler_announced_scripts);

  GUM_DUK_SCRIPT_BACKEND_LOCK ();

  g_hash_table_iter_init (&iter, priv->scripts);

  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &ref))
  {
    GumDukScript * script;

    script = g_weak_ref_get (&ref->instance);
    if (script == NULL)
      continue;
    gum_duk_script_detach_debugger (script);
    g_object_unref (script);
  }

  GUM_DUK_SCRIPT_BACKEND_UNLOCK ();
}

static void
gum_duk_script_backend_on_script_added (GumDukScriptBackend * self,
                                        GumDukScriptId id,
                                        GumDukScript * script)
{
  GMainContext * context;
  GumNotifyScriptAddedData * d;
  GSource * source;

  context = gum_duk_script_backend_get_debug_context (self);
  if (context == NULL)
    return;

  d = g_slice_new (GumNotifyScriptAddedData);
  d->backend = g_object_ref (self);
  d->id = id;
  g_object_get (script, "name", &d->name, NULL);

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_duk_script_backend_notify_script_added,
      d, (GDestroyNotify) gum_notify_script_added_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_duk_script_backend_notify_script_added (GumNotifyScriptAddedData * d)
{
  GumDukScriptBackendPrivate * priv = d->backend->priv;
  gpointer raw_id = GSIZE_TO_POINTER (d->id);
  gchar * name_escaped, * message;

  if (priv->debug_handler == NULL)
    return FALSE;

  if (!g_hash_table_insert (priv->debug_handler_announced_scripts, raw_id,
      raw_id))
    return FALSE;

  name_escaped = g_strescape (d->name, NULL);
  message = g_strdup_printf ("ADD %u %s.js", d->id, name_escaped);

  priv->debug_handler (message, priv->debug_handler_data);

  g_free (message);
  g_free (name_escaped);

  return FALSE;
}

static void
gum_notify_script_added_data_free (GumNotifyScriptAddedData * d)
{
  g_free (d->name);
  g_object_unref (d->backend);

  g_slice_free (GumNotifyScriptAddedData, d);
}

static void
gum_duk_script_backend_on_script_removed (GumDukScriptBackend * self,
                                          GumDukScriptId id)
{
  GMainContext * context;
  GumNotifyScriptRemovedData * d;
  GSource * source;

  context = gum_duk_script_backend_get_debug_context (self);
  if (context == NULL)
    return;

  d = g_slice_new (GumNotifyScriptRemovedData);
  d->backend = g_object_ref (self);
  d->id = id;

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_duk_script_backend_notify_script_removed,
      d, (GDestroyNotify) gum_notify_script_removed_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_duk_script_backend_notify_script_removed (GumNotifyScriptRemovedData * d)
{
  GumDukScriptBackendPrivate * priv = d->backend->priv;
  gchar * message;

  if (priv->debug_handler == NULL)
    return FALSE;

  if (!g_hash_table_remove (priv->debug_handler_announced_scripts,
      GSIZE_TO_POINTER (d->id)))
    return FALSE;

  message = g_strdup_printf ("REMOVE %u", d->id);

  priv->debug_handler (message, priv->debug_handler_data);

  g_free (message);

  return FALSE;
}

static void
gum_notify_script_removed_data_free (GumNotifyScriptRemovedData * d)
{
  g_object_unref (d->backend);

  g_slice_free (GumNotifyScriptRemovedData, d);
}

static void
gum_duk_script_backend_on_debugger_detached (GumDukScript * script,
                                             GumDukScriptWeakRef * ref)
{
  GMainContext * context;
  GumNotifyDebuggerDetachedData * d;
  GSource * source;

  (void) script;

  context = gum_duk_script_backend_get_debug_context (ref->backend);
  if (context == NULL)
    return;

  d = g_slice_new (GumNotifyDebuggerDetachedData);
  d->backend = g_object_ref (ref->backend);
  d->id = ref->id;

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_duk_script_backend_notify_debugger_detached,
      d, (GDestroyNotify) gum_notify_debugger_detached_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_duk_script_backend_notify_debugger_detached (
    GumNotifyDebuggerDetachedData * d)
{
  GumDukScriptBackendPrivate * priv = d->backend->priv;
  gchar * message;

  if (priv->debug_handler == NULL)
    return FALSE;

  message = g_strdup_printf ("DETACH %u", d->id);

  priv->debug_handler (message, priv->debug_handler_data);

  g_free (message);

  return FALSE;
}

static void
gum_notify_debugger_detached_data_free (GumNotifyDebuggerDetachedData * d)
{
  g_object_unref (d->backend);

  g_slice_free (GumNotifyDebuggerDetachedData, d);
}

static void
gum_duk_script_backend_on_debugger_output (GumDukScript * script,
                                           GBytes * bytes,
                                           GumDukScriptWeakRef * ref)
{
  GMainContext * context;
  GumNotifyDebuggerOutputData * d;
  GSource * source;

  (void) script;

  context = gum_duk_script_backend_get_debug_context (ref->backend);
  if (context == NULL)
    return;

  d = g_slice_new (GumNotifyDebuggerOutputData);
  d->backend = g_object_ref (ref->backend);
  d->id = ref->id;
  d->bytes = g_bytes_ref (bytes);

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_duk_script_backend_notify_debugger_output,
      d, (GDestroyNotify) gum_notify_debugger_output_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_duk_script_backend_notify_debugger_output (GumNotifyDebuggerOutputData * d)
{
  GumDukScriptBackendPrivate * priv = d->backend->priv;
  GString * message;
  gconstpointer data;
  gsize size;
  gchar * cur;
  gint state, save;
  const gboolean break_lines = FALSE;

  if (priv->debug_handler == NULL)
    return FALSE;

  data = g_bytes_get_data (d->bytes, &size);

  message = g_string_sized_new (4 + 1 + 20 + 1 +
      (size / 3 + 1) * 4 + 4 + 4 + 1);

  g_string_append_printf (message, "EMIT %u ", d->id);

  cur = message->str + message->len;
  state = 0;
  save = 0;
  cur += g_base64_encode_step (data, size, break_lines, cur, &state, &save);
  cur += g_base64_encode_close (break_lines, cur, &state, &save);
  *cur++ = '\0';
  message->len = cur - message->str;
  g_assert_cmpuint (message->len + 1, <=, message->allocated_len);

  priv->debug_handler (message->str, priv->debug_handler_data);

  g_string_free (message, TRUE);

  return FALSE;
}

static void
gum_notify_debugger_output_data_free (GumNotifyDebuggerOutputData * d)
{
  g_bytes_unref (d->bytes);
  g_object_unref (d->backend);

  g_slice_free (GumNotifyDebuggerOutputData, d);
}

static void
gum_duk_script_backend_on_fatal_error (void * udata,
                                       const char * msg)
{
  (void) udata;

  g_log ("DUK", G_LOG_LEVEL_ERROR, "%s", msg);
  abort ();
}

static void *
gum_duk_alloc (void * udata,
               duk_size_t size)
{
  (void) udata;

  return g_malloc (size);
}

static void *
gum_duk_realloc (void * udata,
                 void * ptr,
                 duk_size_t size)
{
  (void) udata;

  return g_realloc (ptr, size);
}

static void
gum_duk_free (void * udata,
              void * ptr)
{
  (void) udata;

  g_free (ptr);
}
